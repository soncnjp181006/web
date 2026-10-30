/**
 * Tiny hand-rolled Dependency Injection container.
 * Services register here and are injected into routers (factory receives the container).
 */
const registry = new Map();
const singletons = new Map();

function register(name, definition, opts = {}) {
  registry.set(name, {
    definition,
    isFactory: opts.factory !== false && typeof definition === "function",
  });
}

function resolve(name) {
  if (!registry.has(name)) throw new Error(`[DI] unknown service "${name}"`);
  const entry = registry.get(name);
  if (!entry.isFactory) return entry.definition;
  if (singletons.has(name)) return singletons.get(name);
  const instance = entry.definition(module.exports);
  singletons.set(name, instance);
  return instance;
}

function has(name) {
  return registry.has(name);
}

module.exports = { register, resolve, has };
