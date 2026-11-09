import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const tokenPath = join(root, 'src/design-system/tokens.css');
const namedColors = new RegExp(`\\b(?:${[
  'aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue blueviolet brown burlywood cadetblue chartreuse chocolate coral cornflowerblue cornsilk crimson cyan',
  'darkblue darkcyan darkgoldenrod darkgray darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkorange darkorchid darkred darksalmon darkseagreen darkslateblue darkslategray darkslategrey darkturquoise darkviolet',
  'deeppink deepskyblue dimgray dimgrey dodgerblue firebrick floralwhite forestgreen fuchsia gainsboro ghostwhite gold goldenrod gray green greenyellow grey honeydew hotpink indianred indigo ivory khaki',
  'lavender lavenderblush lawngreen lemonchiffon lightblue lightcoral lightcyan lightgoldenrodyellow lightgray lightgreen lightgrey lightpink lightsalmon lightseagreen lightskyblue lightslategray lightslategrey lightsteelblue lightyellow lime limegreen linen',
  'magenta maroon mediumaquamarine mediumblue mediumorchid mediumpurple mediumseagreen mediumslateblue mediumspringgreen mediumturquoise mediumvioletred midnightblue mintcream mistyrose moccasin navajowhite navy',
  'oldlace olive olivedrab orange orangered orchid palegoldenrod palegreen paleturquoise palevioletred papayawhip peachpuff peru pink plum powderblue purple rebeccapurple red rosybrown royalblue',
  'saddlebrown salmon sandybrown seagreen seashell sienna silver skyblue slateblue slategray slategrey snow springgreen steelblue tan teal thistle tomato turquoise violet wheat white whitesmoke yellow yellowgreen',
].join(' ').replaceAll(' ', '|')})\\b`, 'i');

export function readThemes(css) {
  const themes = { light: {}, dark: {} };
  for (const [, selector, body] of css.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (!selector.includes(':root')) continue;
    const theme = /data-theme\s*=\s*['"]?dark/.test(selector) ? themes.dark : themes.light;
    for (const [, name, value] of body.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/g)) {
      theme[name] = value.trim();
    }
  }
  return themes;
}

function resolveColor(value, tokens, seen = new Set()) {
  const alias = /^var\((--[a-z0-9-]+)\)$/.exec(value);
  if (!alias) return value;
  if (seen.has(alias[1]) || !tokens[alias[1]]) throw new Error(`Unresolved color alias: ${value}`);
  seen.add(alias[1]);
  return resolveColor(tokens[alias[1]], tokens, seen);
}

function luminance(color) {
  if (!/^#[a-f\d]{6}$/i.test(color)) throw new Error(`Contrast colors must be opaque six-digit hex: ${color}`);
  const channels = [1, 3, 5].map((start) => parseInt(color.slice(start, start + 2), 16) / 255)
    .map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}

export function contrast(first, second) {
  const values = [luminance(first), luminance(second)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

function files(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : [path];
  });
}

export function unauthorizedColors(source) {
  const clean = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
  const results = [];
  if (/#(?:[a-f\d]{8}|[a-f\d]{6}|[a-f\d]{4}|[a-f\d]{3})\b/i.test(clean)) results.push('hex color outside tokens');
  if (/\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\s*\(/i.test(clean)) results.push('color function outside tokens');
  const colorDeclaration = /(?:^|[;{,\s])["']?(?:color|background(?:-?color)?|border(?:-?(?:top|right|bottom|left))?(?:-?color)?|outline(?:-?color)?|fill|stroke|box-?shadow|text-?shadow|accent-?color|caret-?color|text-?decoration-?color|column-?rule-?color)["']?\s*[:=]\s*([^;\n}]+)/gi;
  for (const [, value] of clean.matchAll(colorDeclaration)) {
    const literals = value.replace(/var\(--[a-z0-9-]+\)/g, '');
    if (namedColors.test(literals)) results.push(`named color outside tokens: ${value.trim()}`);
  }
  return results;
}

export function undeclaredTokenReferences(source, declarations) {
  const clean = source.replace(/\/\*[\s\S]*?\*\//g, '');
  const references = [...clean.matchAll(/\bvar\(\s*(--[a-zA-Z0-9_-]+)/g)].map((match) => match[1]);
  return [...new Set(references)].filter((name) => !declarations.has(name));
}

export function checkDesignSystem() {
  const errors = [];
  const css = readFileSync(tokenPath, 'utf8');
  const themes = readThemes(css);
  const keys = (theme) => Object.keys(theme).filter((name) => name.startsWith('--color-')).sort();
  if (keys(themes.light).length < 35) errors.push('Semantic color contract is incomplete');
  if (JSON.stringify(keys(themes.light)) !== JSON.stringify(keys(themes.dark))) errors.push('Light and Dark must declare the same semantic color tokens');
  const sources = files(join(root, 'src')).filter((path) => /\.(css|[jt]sx?)$/.test(path))
    .map((path) => ({ path, content: readFileSync(path, 'utf8') }));
  const declarations = new Set(sources.filter(({ path }) => path.endsWith('.css')).flatMap(({ content }) =>
    [...content.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(/(--[a-zA-Z0-9_-]+)\s*:/g)].map((match) => match[1])));
  for (const { path, content } of sources) {
    for (const name of undeclaredTokenReferences(content, declarations)) {
      errors.push(`${relative(root, path)}: undeclared CSS token ${name}`);
    }
    if (path === tokenPath) continue;
    for (const problem of unauthorizedColors(content)) errors.push(`${relative(root, path)}: ${problem}`);
    if (/prefers-color-scheme/.test(content)) errors.push(`${relative(root, path)}: automatic system theme is prohibited`);
    if (/\.brand-image[^}]*\b(?:filter|mix-blend-mode)\s*:/s.test(content)) errors.push(`${relative(root, path)}: logo filters/blending are prohibited`);
  }

  const pairs = [];
  for (const background of ['background', 'surface', 'surface-elevated', 'header', 'sidebar', 'input', 'table-hover', 'table-selected', 'modal', 'menu']) {
    pairs.push(['text', background, 4.5]);
  }
  for (const background of ['background', 'surface', 'surface-elevated']) pairs.push(['text-secondary', background, 4.5]);
  pairs.push(['button-primary-text', 'button-primary', 4.5]);
  pairs.push(['button-primary-text', 'button-primary-hover', 4.5]);
  pairs.push(['button-secondary-text', 'button-secondary', 4.5]);
  pairs.push(['button-secondary-text', 'button-secondary-hover', 4.5]);
  pairs.push(['input-text', 'input', 4.5]);
  pairs.push(['input-placeholder', 'input', 4.5]);
  pairs.push(['nav-selected-text', 'nav-selected', 4.5]);
  pairs.push(['tooltip-text', 'tooltip', 4.5]);
  pairs.push(['info-text', 'notification', 4.5]);
  for (const status of ['success', 'warning', 'error', 'info']) pairs.push([`${status}-text`, `${status}-bg`, 4.5]);
  pairs.push(['border-control', 'input', 3]);
  pairs.push(['focus', 'surface', 3]);
  pairs.push(['focus', 'background', 3]);
  pairs.push(['focus', 'input', 3]);
  for (let index = 1; index <= 4; index++) pairs.push([`chart-${index}`, 'surface', 3]);
  for (const [name, own] of Object.entries(themes)) {
    const tokens = { ...themes.light, ...own };
    for (const [textName, backgroundName, minimum] of pairs) {
      const text = tokens[`--color-${textName}`];
      const background = tokens[`--color-${backgroundName}`];
      if (!text || !background) { errors.push(`${name}: missing contrast pair ${textName}/${backgroundName}`); continue; }
      try {
        const ratio = contrast(resolveColor(text, tokens), resolveColor(background, tokens));
        if (ratio < minimum) errors.push(`${name}: ${textName}/${backgroundName} ${ratio.toFixed(2)}:1 is below ${minimum}:1`);
      } catch (error) { errors.push(`${name}: ${error.message}`); }
    }
  }
  return { errors, colorTokens: keys(themes.light).length, contrastPairs: pairs.length * 2 };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = checkDesignSystem();
  if (result.errors.length) {
    console.error(result.errors.join('\n'));
    process.exitCode = 1;
  } else {
    console.log(`Design System policy passed (${result.colorTokens} semantic colors, ${result.contrastPairs} contrast pairs).`);
  }
}
