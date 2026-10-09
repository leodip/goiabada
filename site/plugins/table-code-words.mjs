// A hast plugin for Sätteri, Astro's Markdown processor, that keeps each hyphenated word of code in
// a table cell whole. A hyphen is a place a line may break, in code as in prose, so a table
// squeezing a column to fit split `goiabada-authserver` after its hyphen, and no CSS property turns
// that off short of `white-space: nowrap`. Each word with a hyphen goes into a span of class
// code-word, which custom.css keeps on one line. The spaces between words are left as they are, so
// a log message or a `POST /path` in a cell still wraps there. The text is unchanged: copying the
// code gives the hyphens it had. Code outside a table, where a line breaking at a hyphen is the
// least bad choice, and code blocks are not touched.

const cellTags = new Set(['td', 'th']);

export const tableCodeWords = {
	name: 'table-code-words',
	element: {
		filter: ['code'],
		visit(node, ctx) {
			if (!inTableCell(node, ctx)) return;
			if (!node.children.some((child) => child.type === 'text' && child.value.includes('-'))) return;
			return {
				type: 'element',
				tagName: node.tagName,
				properties: { ...node.properties },
				children: node.children.flatMap(splitWords),
			};
		},
	},
};

function inTableCell(node, ctx) {
	for (let parent = ctx.parent(node); parent !== undefined; parent = ctx.parent(parent)) {
		if (parent.type !== 'element') continue;
		if (parent.tagName === 'pre') return false;
		if (cellTags.has(parent.tagName)) return true;
	}
	return false;
}

function splitWords(node) {
	if (node.type !== 'text' || !node.value.includes('-')) return [node];
	return node.value
		.split(/(\s+)/)
		.filter((part) => part !== '')
		.map((part) =>
			part.includes('-')
				? {
						type: 'element',
						tagName: 'span',
						properties: { className: ['code-word'] },
						children: [{ type: 'text', value: part }],
					}
				: { type: 'text', value: part },
		);
}
