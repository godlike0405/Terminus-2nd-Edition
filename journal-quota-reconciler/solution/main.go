package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type FS struct {
	ID       string `json:"id"`
	IODomain string `json:"io_domain"`
	Capacity int64  `json:"capacity_bytes"`
	Free     int64  `json:"free_bytes"`
}
type NS struct {
	Name        string   `json:"name"`
	Filesystem  string   `json:"filesystem"`
	Usage       int64    `json:"usage_bytes"`
	Oldest      int64    `json:"oldest_unix"`
	VacuumAfter []string `json:"vacuum_after"`
}
type Inv struct {
	Filesystems []FS `json:"filesystems"`
	Namespaces  []NS `json:"namespaces"`
}
type FP struct {
	Reserve int64            `json:"reserve_bytes"`
	Budget  int64            `json:"budget_bytes"`
	Pools   map[string]Limit `json:"pools"`
}
type Limit struct {
	Floor  int64 `json:"floor_bytes"`
	Cap    int64 `json:"cap_bytes"`
	Weight int64 `json:"weight"`
}
type NP struct {
	Pool     string `json:"pool"`
	Floor    int64  `json:"floor_bytes"`
	Cap      int64  `json:"cap_bytes"`
	Weight   int64  `json:"weight"`
	Priority int64  `json:"priority"`
}
type Pol struct {
	Parallelism int64         `json:"vacuum_parallelism"`
	Filesystems map[string]FP `json:"filesystems"`
	Namespaces  map[string]NP `json:"namespaces"`
}
type FOut struct {
	ID          string `json:"id"`
	Allocatable int64  `json:"allocatable_bytes"`
	Allocated   int64  `json:"allocated_bytes"`
	Unallocated int64  `json:"unallocated_bytes"`
	Pools       []POut `json:"pools"`
}
type POut struct {
	Name        string `json:"name"`
	Allocation  int64  `json:"allocation_bytes"`
	Allocated   int64  `json:"allocated_bytes"`
	Unallocated int64  `json:"unallocated_bytes"`
}
type Act struct {
	Wave       int64  `json:"wave"`
	Namespace  string `json:"namespace"`
	Filesystem string `json:"filesystem"`
	Usage      int64  `json:"usage_bytes"`
	Target     int64  `json:"target_bytes"`
	Reclaim    int64  `json:"reclaim_bytes"`
}
type Plan struct {
	Filesystems []FOut `json:"filesystems"`
	Vacuum      []Act  `json:"vacuum"`
}

func decode(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(v); e != nil {
		return e
	}
	if d.More() {
		return errors.New("trailing JSON")
	}
	return nil
}
func validate(i Inv, p Pol) error {
	if p.Parallelism <= 0 {
		return errors.New("invalid vacuum parallelism")
	}
	fm := map[string]FS{}
	nm := map[string]bool{}
	for _, f := range i.Filesystems {
		if f.ID == "" || f.IODomain == "" || f.Capacity < 0 || f.Free < 0 || f.Free > f.Capacity || fm[f.ID].ID != "" {
			return errors.New("invalid filesystem")
		}
		fm[f.ID] = f
		q, ok := p.Filesystems[f.ID]
		if !ok || q.Reserve < 0 || q.Budget < 0 || q.Reserve > f.Capacity || q.Budget > f.Capacity-q.Reserve {
			return errors.New("invalid filesystem policy")
		}
	}
	if len(fm) != len(p.Filesystems) {
		return errors.New("extra filesystem policy")
	}
	poolMembers := map[string]int{}
	namespaceFloors := map[string]int64{}
	for _, n := range i.Namespaces {
		if n.Name == "" || nm[n.Name] || n.Usage < 0 || n.Oldest < 0 || fm[n.Filesystem].ID == "" {
			return errors.New("invalid namespace")
		}
		nm[n.Name] = true
		q, ok := p.Namespaces[n.Name]
		fp := p.Filesystems[n.Filesystem]
		if !ok || q.Pool == "" || fp.Pools[q.Pool].Weight == 0 || q.Floor < 0 || q.Cap < q.Floor || q.Weight <= 0 || q.Priority < 0 {
			return errors.New("invalid namespace policy")
		}
		key := n.Filesystem + "\x00" + q.Pool
		poolMembers[key]++
		namespaceFloors[key] += q.Floor
	}
	if len(nm) != len(p.Namespaces) {
		return errors.New("extra namespace policy")
	}
	dependencies := map[string][]string{}
	for _, n := range i.Namespaces {
		seen := map[string]bool{}
		for _, dep := range n.VacuumAfter {
			if dep == n.Name || seen[dep] || !nm[dep] {
				return errors.New("invalid vacuum dependency")
			}
			seen[dep] = true
		}
		dependencies[n.Name] = n.VacuumAfter
	}
	state := map[string]int{}
	var visit func(string) bool
	visit = func(name string) bool {
		if state[name] == 1 {
			return false
		}
		if state[name] == 2 {
			return true
		}
		state[name] = 1
		for _, dep := range dependencies[name] {
			if !visit(dep) {
				return false
			}
		}
		state[name] = 2
		return true
	}
	for name := range nm {
		if !visit(name) {
			return errors.New("cyclic vacuum dependencies")
		}
	}
	for id, f := range fm {
		q := p.Filesystems[id]
		a := q.Budget
		if f.Capacity-q.Reserve < a {
			a = f.Capacity - q.Reserve
		}
		var poolFloors int64
		for name, pool := range q.Pools {
			if name == "" || pool.Floor < 0 || pool.Cap < pool.Floor || pool.Weight <= 0 {
				return errors.New("invalid pool policy")
			}
			key := id + "\x00" + name
			if poolMembers[key] == 0 || namespaceFloors[key] > pool.Floor {
				return errors.New("invalid pool membership or floors")
			}
			poolFloors += pool.Floor
		}
		if poolFloors > a {
			return errors.New("pool floors exceed allocation")
		}
	}
	return nil
}
func allocate(names []string, limits map[string]Limit, total int64) map[string]int64 {
	a := map[string]int64{}
	var used int64
	for _, name := range names {
		a[name] = limits[name].Floor
		used += a[name]
	}
	rem := total - used
	for rem > 0 {
		active := []string{}
		var weights int64
		for _, name := range names {
			q := limits[name]
			if a[name] < q.Cap {
				active = append(active, name)
				weights += q.Weight
			}
		}
		if len(active) == 0 {
			break
		}
		var gave int64
		initial := rem
		for _, name := range active {
			q := limits[name]
			x := initial * q.Weight / weights
			if x > q.Cap-a[name] {
				x = q.Cap - a[name]
			}
			a[name] += x
			gave += x
		}
		rem -= gave
		sort.Strings(active)
		for _, name := range active {
			if rem == 0 {
				break
			}
			if a[name] < limits[name].Cap {
				a[name]++
				rem--
				gave++
			}
		}
		if gave == 0 {
			break
		}
	}
	return a
}
func escape(s string) string {
	var b strings.Builder
	for _, x := range []byte(s) {
		if x >= 'a' && x <= 'z' || x >= 'A' && x <= 'Z' || x >= '0' && x <= '9' || x == '_' || x == '.' {
			b.WriteByte(x)
		} else {
			fmt.Fprintf(&b, "\\x%02x", x)
		}
	}
	return b.String()
}

func schedule(actions []Act, i Inv, p Pol) []Act {
	byName := map[string]Act{}
	namespaces := map[string]NS{}
	domains := map[string]string{}
	for _, f := range i.Filesystems {
		domains[f.ID] = f.IODomain
	}
	for _, n := range i.Namespaces {
		namespaces[n.Name] = n
	}
	for _, action := range actions {
		byName[action.Namespace] = action
	}
	done := map[string]bool{}
	result := []Act{}
	for len(done) < len(byName) {
		ready := []Act{}
		for name, action := range byName {
			if done[name] {
				continue
			}
			ok := true
			for _, dep := range namespaces[name].VacuumAfter {
				if _, required := byName[dep]; required && !done[dep] {
					ok = false
				}
			}
			if ok {
				ready = append(ready, action)
			}
		}
		sort.Slice(ready, func(x, y int) bool {
			px, py := p.Namespaces[ready[x].Namespace], p.Namespaces[ready[y].Namespace]
			if px.Priority != py.Priority {
				return px.Priority > py.Priority
			}
			nx, ny := namespaces[ready[x].Namespace], namespaces[ready[y].Namespace]
			if nx.Oldest != ny.Oldest {
				return nx.Oldest < ny.Oldest
			}
			return nx.Name < ny.Name
		})
		usedDomains := map[string]bool{}
		wave := int64(0)
		if len(result) > 0 {
			wave = result[len(result)-1].Wave + 1
		}
		selected := int64(0)
		for _, action := range ready {
			domain := domains[action.Filesystem]
			if selected == p.Parallelism || usedDomains[domain] {
				continue
			}
			action.Wave = wave
			result = append(result, action)
			done[action.Namespace] = true
			usedDomains[domain] = true
			selected++
		}
	}
	return result
}

func run(ip, pp, out string) error {
	if !filepath.IsAbs(out) {
		return errors.New("output must be absolute")
	}
	var i Inv
	var p Pol
	if e := decode(ip, &i); e != nil {
		return e
	}
	if e := decode(pp, &p); e != nil {
		return e
	}
	if e := validate(i, p); e != nil {
		return e
	}
	sort.Slice(i.Filesystems, func(a, b int) bool { return i.Filesystems[a].ID < i.Filesystems[b].ID })
	plan := Plan{Filesystems: []FOut{}, Vacuum: []Act{}}
	configs := map[string]string{}
	for _, f := range i.Filesystems {
		q := p.Filesystems[f.ID]
		total := q.Budget
		if f.Capacity-q.Reserve < total {
			total = f.Capacity - q.Reserve
		}
		names := []NS{}
		for _, n := range i.Namespaces {
			if n.Filesystem == f.ID {
				names = append(names, n)
			}
		}
		poolNames := make([]string, 0, len(q.Pools))
		for name := range q.Pools {
			poolNames = append(poolNames, name)
		}
		sort.Strings(poolNames)
		poolAlloc := allocate(poolNames, q.Pools, total)
		a := map[string]int64{}
		poolOut := []POut{}
		var used int64
		for _, poolName := range poolNames {
			memberNames := []string{}
			limits := map[string]Limit{}
			for _, n := range names {
				np := p.Namespaces[n.Name]
				if np.Pool == poolName {
					memberNames = append(memberNames, n.Name)
					limits[n.Name] = Limit{np.Floor, np.Cap, np.Weight}
				}
			}
			memberAlloc := allocate(memberNames, limits, poolAlloc[poolName])
			var poolUsed int64
			for name, amount := range memberAlloc {
				a[name] = amount
				poolUsed += amount
			}
			used += poolUsed
			poolOut = append(poolOut, POut{poolName, poolAlloc[poolName], poolUsed, poolAlloc[poolName] - poolUsed})
		}
		acts := []Act{}
		for _, n := range names {
			configs[escape(n.Name)+".conf"] = fmt.Sprintf("[Journal]\nSystemMaxUse=%d\nSystemKeepFree=%d\n", a[n.Name], q.Reserve)
			if n.Usage > a[n.Name] {
				acts = append(acts, Act{Namespace: n.Name, Filesystem: f.ID, Usage: n.Usage, Target: a[n.Name], Reclaim: n.Usage - a[n.Name]})
			}
		}
		plan.Vacuum = append(plan.Vacuum, acts...)
		plan.Filesystems = append(plan.Filesystems, FOut{f.ID, total, used, total - used, poolOut})
	}
	plan.Vacuum = schedule(plan.Vacuum, i, p)
	parent := filepath.Dir(out)
	tmpRoot, e := os.MkdirTemp(parent, ".journal-reconcile-tmp-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmpRoot)
	tmp := filepath.Join(tmpRoot, "tree")
	if e := os.MkdirAll(filepath.Join(tmp, "journald"), 0755); e != nil {
		return e
	}
	for n, v := range configs {
		if e := os.WriteFile(filepath.Join(tmp, "journald", n), []byte(v), 0644); e != nil {
			os.RemoveAll(tmp)
			return e
		}
	}
	fsj := []map[string]any{}
	for _, f := range plan.Filesystems {
		pools := []map[string]any{}
		for _, p := range f.Pools {
			pools = append(pools, map[string]any{"name": p.Name, "allocation_bytes": p.Allocation, "allocated_bytes": p.Allocated, "unallocated_bytes": p.Unallocated})
		}
		fsj = append(fsj, map[string]any{"id": f.ID, "allocatable_bytes": f.Allocatable, "allocated_bytes": f.Allocated, "unallocated_bytes": f.Unallocated, "pools": pools})
	}
	vj := []map[string]any{}
	for _, a := range plan.Vacuum {
		vj = append(vj, map[string]any{"wave": a.Wave, "namespace": a.Namespace, "filesystem": a.Filesystem, "usage_bytes": a.Usage, "target_bytes": a.Target, "reclaim_bytes": a.Reclaim})
	}
	b, e := json.Marshal(map[string]any{"filesystems": fsj, "vacuum": vj})
	if e == nil {
		e = os.WriteFile(filepath.Join(tmp, "plan.json"), append(b, '\n'), 0644)
	}
	if e != nil {
		os.RemoveAll(tmp)
		return e
	}
	oldRoot, e := os.MkdirTemp(parent, ".journal-reconcile-old-")
	if e != nil {
		return e
	}
	os.Remove(oldRoot)
	old := oldRoot
	if _, e = os.Stat(out); e == nil {
		if e = os.Rename(out, old); e != nil {
			os.RemoveAll(tmp)
			return e
		}
	}
	if e = os.Rename(tmp, out); e != nil {
		os.Rename(old, out)
		return e
	}
	os.RemoveAll(old)
	return nil
}
func main() {
	ip := flag.String("inventory", "", "")
	pp := flag.String("policy", "", "")
	o := flag.String("output", "", "")
	flag.Parse()
	if *ip == "" || *pp == "" || *o == "" {
		os.Exit(2)
	}
	if e := run(*ip, *pp, *o); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
