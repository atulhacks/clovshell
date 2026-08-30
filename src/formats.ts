// Output formatters: turn raw shellcode bytes into ready-to-paste
// literals for various languages.

export interface FormatDef {
  id: string;
  label: string;
  /** file extension for the download button */
  ext: string;
  make: (bytes: Uint8Array) => string;
}

function wrapList(items: string[], indent: string, width = 78): string {
  const lines: string[] = [];
  let line = '';
  for (const item of items) {
    const piece = (line ? ', ' : '') + item;
    if (indent.length + line.length + piece.length > width && line) {
      lines.push(line + ',');
      line = item;
    } else {
      line += piece;
    }
  }
  if (line) lines.push(line);
  return lines.join('\n' + indent);
}

/** \xNN escapes with quote/backslash escaping, e.g. b"..." contents */
function escapedLiteral(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    if (b === 0x22) out += '\\"';
    else if (b === 0x5c) out += '\\\\';
    else out += '\\x' + b.toString(16).padStart(2, '0');
  }
  return out;
}

function hexBytes(bytes: Uint8Array): string[] {
  return Array.from(bytes, (b) => '0x' + b.toString(16).padStart(2, '0'));
}

export const FORMATS: FormatDef[] = [
  {
    id: 'python',
    label: 'Python',
    ext: 'py',
    make: (b) => (b.length ? `b"${escapedLiteral(b)}"` : 'b""'),
  },
  {
    id: 'python-array',
    label: 'Python array',
    ext: 'py',
    make: (b) => `shellcode = [\n    ${wrapList(hexBytes(b), '    ') || ''}\n]`,
  },
  {
    id: 'c',
    label: 'C',
    ext: 'c',
    make: (b) =>
      b.length
        ? `unsigned char shellcode[] = {\n    ${wrapList(hexBytes(b), '    ')}\n};`
        : 'unsigned char shellcode[] = { 0 };',
  },
  {
    id: 'c-string',
    label: 'C string',
    ext: 'c',
    make: (b) => `"${escapedLiteral(b)}\\x00"`,
  },
  {
    id: 'escaped',
    label: 'Escaped',
    ext: 'txt',
    make: (b) => escapedLiteral(b),
  },
  {
    id: 'javascript',
    label: 'JavaScript',
    ext: 'js',
    make: (b) =>
      b.length
        ? `const shellcode = new Uint8Array([\n    ${wrapList(hexBytes(b), '    ')}\n]);`
        : 'const shellcode = new Uint8Array([]);',
  },
  {
    id: 'nasm',
    label: 'NASM',
    ext: 'asm',
    make: (b) =>
      b.length
        ? `shellcode: db ${wrapList(hexBytes(b), '        ', 72).replaceAll('\n', '\n        ')}`
        : 'shellcode: db ',
  },
  {
    id: 'base64',
    label: 'Base64',
    ext: 'txt',
    make: (b) => {
      let bin = '';
      for (const byte of b) bin += String.fromCharCode(byte);
      return btoa(bin);
    },
  },
  {
    id: 'powershell',
    label: 'PowerShell',
    ext: 'ps1',
    make: (b) =>
      b.length
        ? `[Byte[]] $shellcode = ${wrapList(hexBytes(b), '    ').replaceAll('\n', '\n')}`
        : '[Byte[]] $shellcode = @()',
  },
  {
    id: 'csharp',
    label: 'C#',
    ext: 'cs',
    make: (b) =>
      b.length
        ? `byte[] shellcode = new byte[] {\n    ${wrapList(hexBytes(b), '    ')}\n};`
        : 'byte[] shellcode = Array.Empty<byte>();',
  },
  {
    id: 'java',
    label: 'Java',
    ext: 'java',
    make: (b) => {
      const signed = Array.from(b, (x) => `(byte) 0x${x.toString(16).padStart(2, '0')}`);
      return b.length
        ? `byte[] shellcode = new byte[] {\n    ${wrapList(signed, '    ')}\n};`
        : 'byte[] shellcode = new byte[0];';
    },
  },
  {
    id: 'ruby',
    label: 'Ruby',
    ext: 'rb',
    make: (b) => `shellcode = "${escapedLiteral(b)}".b`,
  },
  {
    id: 'rust',
    label: 'Rust',
    ext: 'rs',
    make: (b) =>
      b.length
        ? `let shellcode: [u8; ${b.length}] = [\n    ${wrapList(hexBytes(b), '    ')}\n];`
        : 'let shellcode: [u8; 0] = [];',
  },
  {
    id: 'yara',
    label: 'YARA',
    ext: 'yar',
    make: (b) => {
      const pairs = Array.from(b, (x) => x.toString(16).padStart(2, '0').toUpperCase());
      return `rule shellcode {\n  strings:\n    $s = { ${pairs.join(' ')} }\n  condition:\n    $s\n}`;
    },
  },
];
