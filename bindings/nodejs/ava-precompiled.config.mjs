export default {
  files: ['__test__/*.spec.js'],
  timeout: '5m',
  workerThreads: false,
  // V8 JIT compilers crash under QEMU TCG s390x emulation; use interpreter only.
  // WebAssembly (Liftoff) remains available for Node's built-in HTTP parser.
  nodeArguments: ['--no-turbofan', '--no-maglev', '--no-sparkplug'],
};
