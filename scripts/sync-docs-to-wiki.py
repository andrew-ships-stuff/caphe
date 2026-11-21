#!/usr/bin/env python3
"""Flatten a docs tree into a GitHub wiki working copy.

Nested directories become hyphenated page names (GitHub wikis have no real
folders), relative .md links are rewritten to wiki page links, and Home.md
gets a nested table of contents.
"""
import os
import re
import sys

LINK = re.compile(r'\[([^\]]*)\]\(([^)\s]+)((?:\s+"[^"]*")?)\)')


def page_name(rel):
    return rel[:-3].replace('/', '-')


def title_of(text, rel):
    for line in text.splitlines():
        if line.startswith('# '):
            return line[2:].strip()
    return os.path.splitext(os.path.basename(rel))[0].replace('-', ' ')


def rewrite(text, rel, names):
    def repl(m):
        label, target, title = m.group(1), m.group(2), m.group(3)
        if target.startswith('#') or re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', target):
            return m.group(0)
        path, _, frag = target.partition('#')
        if not path.endswith('.md'):
            return m.group(0)
        base = os.path.normpath(os.path.join(os.path.dirname(rel), path)).replace(os.sep, '/')
        if base not in names:
            return m.group(0)
        dest = page_name(base)
        return f'[{label}]({dest}{("#" + frag) if frag else ""}{title})'

    return LINK.sub(repl, text)


def main():
    if len(sys.argv) != 3:
        sys.exit('usage: sync-docs-to-wiki.py DOCS_DIR WIKI_DIR')
    docs, wiki = sys.argv[1], sys.argv[2]

    rels = []
    for root, _, files in os.walk(docs):
        for f in files:
            if f.endswith('.md'):
                rel = os.path.relpath(os.path.join(root, f), docs).replace(os.sep, '/')
                rels.append(rel)
    rels.sort()
    names = set(rels)

    used = set()
    pages = []
    for rel in rels:
        with open(os.path.join(docs, rel), encoding='utf-8') as fh:
            text = fh.read()
        name = page_name(rel)
        suffix = 2
        while name in used:
            name = f'{page_name(rel)}-{suffix}'
            suffix += 1
        used.add(name)
        with open(os.path.join(wiki, name + '.md'), 'w', encoding='utf-8') as fh:
            fh.write(rewrite(text, rel, names))
        pages.append((rel, name, title_of(text, rel)))

    lines = ['# Caphe documentation', '']
    last_dir = None
    for rel, name, title in pages:
        d = os.path.dirname(rel)
        if d != last_dir:
            if d:
                lines.append(f'**{d}/**')
            last_dir = d
        indent = '  ' * (d.count('/') + 1 if d else 0)
        lines.append(f'{indent}- [{title}]({name})')
    lines.append('')
    with open(os.path.join(wiki, 'Home.md'), 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines))

    print(f'synced {len(pages)} pages to {wiki}/')


if __name__ == '__main__':
    main()
