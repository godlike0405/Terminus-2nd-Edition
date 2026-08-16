// Mock DNS resolver client. Every name resolution the tool performs — the managed
// domain's SPF TXT, the _dmarc TXT, and the TXT/A/MX records reached while
// expanding SPF include/redirect/a/mx terms — goes through this one HTTP client so
// the whole run is offline and reproducible.
//
//   GET {base}/resolve?name=<name>&type=<TXT|A|MX>
//   -> { "name": "...", "type": "TXT", "status": "NOERROR"|"NXDOMAIN", "records": [...] }

export type RecordType = 'TXT' | 'A' | 'MX';

export interface DnsAnswer {
  status: 'NOERROR' | 'NXDOMAIN';
  records: string[];
}

export interface Resolver {
  query(name: string, type: RecordType): Promise<DnsAnswer>;
}

export function httpResolver(base: string): Resolver {
  return {
    async query(name: string, type: RecordType): Promise<DnsAnswer> {
      const url = `${base}/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`dns query failed for ${name}/${type}: status ${response.status}`);
      }
      const data = (await response.json()) as { status?: string; records?: string[] };
      const status = data.status === 'NXDOMAIN' ? 'NXDOMAIN' : 'NOERROR';
      return { status, records: data.records ?? [] };
    },
  };
}
