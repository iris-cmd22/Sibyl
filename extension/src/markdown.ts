// markdown.ts — convertitore Markdown→HTML minimale (zero dipendenze).
// Copre ciò che produce il report di Sibyl: heading, liste, code block/inline,
// grassetto/corsivo, link, citazioni, righe orizzontali e frontmatter YAML.

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** Rende inline una riga: escape + code/bold/italic/link. */
function inline(text: string): string {
  let s = escapeHtml(text);
  s = s.replace(/`([^`]+)`/g, (_m, c) => `<code>${c}</code>`);
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/(^|[^*])\*([^*]+)\*/g, '$1<em>$2</em>');
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, t, u) => `<a href="${u}">${t}</a>`);
  return s;
}

export function renderMarkdown(md: string): string {
  const lines = md.replace(/\r\n/g, '\n').split('\n');
  let html = '';
  let i = 0;

  // Frontmatter YAML in testa (--- ... ---) → blocco metadati.
  if (lines[0] === '---') {
    const meta: string[] = [];
    i = 1;
    while (i < lines.length && lines[i] !== '---') {
      meta.push(lines[i]);
      i++;
    }
    i++; // salta il --- di chiusura
    if (meta.length) {
      html += `<pre class="frontmatter">${escapeHtml(meta.join('\n'))}</pre>`;
    }
  }

  let inCode = false;
  let codeBuf: string[] = [];
  let listType: 'ul' | 'ol' | null = null;
  const closeList = () => {
    if (listType) {
      html += `</${listType}>`;
      listType = null;
    }
  };

  for (; i < lines.length; i++) {
    const line = lines[i];

    const fence = line.match(/^```/);
    if (fence) {
      if (!inCode) {
        closeList();
        inCode = true;
        codeBuf = [];
      } else {
        html += `<pre><code>${escapeHtml(codeBuf.join('\n'))}</code></pre>`;
        inCode = false;
      }
      continue;
    }
    if (inCode) {
      codeBuf.push(line);
      continue;
    }

    if (/^\s*$/.test(line)) {
      closeList();
      continue;
    }
    if (/^\s*([-*_])\1\1+\s*$/.test(line)) {
      closeList();
      html += '<hr/>';
      continue;
    }

    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      closeList();
      const lvl = h[1].length;
      html += `<h${lvl}>${inline(h[2])}</h${lvl}>`;
      continue;
    }

    const bq = line.match(/^>\s?(.*)$/);
    if (bq) {
      closeList();
      html += `<blockquote>${inline(bq[1])}</blockquote>`;
      continue;
    }

    const ul = line.match(/^\s*[-*+]\s+(.*)$/);
    if (ul) {
      if (listType !== 'ul') {
        closeList();
        html += '<ul>';
        listType = 'ul';
      }
      html += `<li>${inline(ul[1])}</li>`;
      continue;
    }

    const ol = line.match(/^\s*\d+\.\s+(.*)$/);
    if (ol) {
      if (listType !== 'ol') {
        closeList();
        html += '<ol>';
        listType = 'ol';
      }
      html += `<li>${inline(ol[1])}</li>`;
      continue;
    }

    closeList();
    html += `<p>${inline(line)}</p>`;
  }

  closeList();
  if (inCode) {
    html += `<pre><code>${escapeHtml(codeBuf.join('\n'))}</code></pre>`;
  }
  return html;
}
