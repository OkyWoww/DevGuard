import * as fs from 'node:fs';
import * as nodeModule from 'node:module';
import { fileURLToPath } from 'node:url';

if (typeof nodeModule.registerHooks === 'function') {
  nodeModule.registerHooks({
    resolve(specifier, context, nextResolve) {
      try {
        return nextResolve(specifier, context);
      } catch (err) {
        if (specifier.startsWith('.') && specifier.endsWith('.js') && context.parentURL) {
          const tsUrl = new URL(specifier.slice(0, -3) + '.ts', context.parentURL);
          if (fs.existsSync(fileURLToPath(tsUrl))) {
            return nextResolve(tsUrl.href, context);
          }
        }
        throw err;
      }
    },
  });
} else if (typeof nodeModule.register === 'function') {
  const fallbackLoader = [
    "import * as fs from 'node:fs';",
    "import { fileURLToPath } from 'node:url';",
    'export async function resolve(specifier, context, nextResolve) {',
    '  try {',
    '    return await nextResolve(specifier, context);',
    '  } catch (err) {',
    "    if (specifier.startsWith('.') && specifier.endsWith('.js') && context.parentURL) {",
    "      const tsUrl = new URL(specifier.slice(0, -3) + '.ts', context.parentURL);",
    '      if (fs.existsSync(fileURLToPath(tsUrl))) return nextResolve(tsUrl.href, context);',
    '    }',
    '    throw err;',
    '  }',
    '}',
  ].join('\n');
  nodeModule.register('data:text/javascript,' + encodeURIComponent(fallbackLoader));
}

await import('./cli.ts');
