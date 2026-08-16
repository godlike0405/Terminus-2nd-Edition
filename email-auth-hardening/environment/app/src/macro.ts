// SPF macro expansion (RFC 7208 section 7). Macros let an `exists` mechanism build
// a query name from the connecting IP and the current domain — the classic
// `exists:%{ir}.%{d}` reversed-IP allow-list check. A macro is `%{<letter><digits?>
// <r?><delimiters?>}`; `%%`, `%_`, `%-` are literal escapes. `%{ir}` reverses the
// IP's labels; a trailing digit count keeps only that many right-most labels.

export interface MacroContext {
  ip: string; // connecting IPv4, dotted
  domain: string; // the <domain> currently being evaluated
  sender: string; // envelope sender local@domain
}

function macroValue(letter: string, ctx: MacroContext): string {
  const lower = letter.toLowerCase();
  const atSplit = ctx.sender.split('@');
  const local = atSplit.length > 1 ? atSplit[0] : 'postmaster';
  const senderDomain = atSplit.length > 1 ? atSplit[1] : ctx.domain;
  switch (lower) {
    case 's':
      return ctx.sender;
    case 'l':
      return local;
    case 'o':
      return senderDomain;
    case 'd':
      return ctx.domain;
    case 'i':
      return ctx.ip;
    case 'h':
      return ctx.domain;
    case 'v':
      return 'in-addr';
    case 'p':
      return 'unknown';
    default:
      return '';
  }
}

function applyTransformer(value: string, digits: number | null, reverse: boolean, delimiters: string): string {
  const delimSet = delimiters.length > 0 ? delimiters : '.';
  const pattern = new RegExp(`[${delimSet.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&')}]`);
  const parts = value.split(pattern);
  if (digits !== null && digits < parts.length) return parts.slice(parts.length - digits).join('.');
  return parts.join('.');
}

export function expandMacros(spec: string, ctx: MacroContext): string {
  let out = '';
  let i = 0;
  while (i < spec.length) {
    const ch = spec[i];
    if (ch !== '%') {
      out += ch;
      i += 1;
      continue;
    }
    const next = spec[i + 1];
    if (next === '%') {
      out += '%';
      i += 2;
    } else if (next === '_') {
      out += ' ';
      i += 2;
    } else if (next === '-') {
      out += '%20';
      i += 2;
    } else if (next === '{') {
      const close = spec.indexOf('}', i + 2);
      if (close === -1) {
        out += ch;
        i += 1;
        continue;
      }
      const body = spec.slice(i + 2, close);
      const letter = body[0];
      let rest = body.slice(1);
      let digits: number | null = null;
      const digitMatch = rest.match(/^\d+/);
      if (digitMatch) {
        digits = Number.parseInt(digitMatch[0], 10);
        rest = rest.slice(digitMatch[0].length);
      }
      let reverse = false;
      if (rest.startsWith('r') || rest.startsWith('R')) {
        reverse = true;
        rest = rest.slice(1);
      }
      const delimiters = rest;
      out += applyTransformer(macroValue(letter, ctx), digits, reverse, delimiters);
      i = close + 1;
    } else {
      out += ch;
      i += 1;
    }
  }
  return out;
}
