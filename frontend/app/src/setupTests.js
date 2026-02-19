// jest-dom adds custom jest matchers for asserting on DOM nodes.
// allows you to do things like:
// expect(element).toHaveTextContent(/react/i)
// learn more: https://github.com/testing-library/jest-dom
import '@testing-library/jest-dom';
import { TextEncoder, TextDecoder } from 'util';

Object.assign(global, { TextEncoder, TextDecoder });

// Polyfill ResizeObserver (needed for Recharts)
global.ResizeObserver = class ResizeObserver {
   observe() { }
   unobserve() { }
   disconnect() { }
};

// Polyfill matchMedia
global.matchMedia = global.matchMedia || function (query) {
   return {
      matches: false,
      media: query,
      onchange: null,
      addListener: jest.fn(), // deprecated
      removeListener: jest.fn(), // deprecated
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
   };
};

// Polyfill BroadcastChannel for MSW
global.BroadcastChannel = class BroadcastChannel {
   constructor(name) {
      this.name = name;
   }
   postMessage() { }
   close() { }
   addEventListener() { }
   removeEventListener() { }
};

// Polyfill TransformStream for MSW
global.TransformStream = class TransformStream {
   constructor() {
      this.readable = {};
      this.writable = {};
   }
};

// Polyfill WritableStream for MSW
global.WritableStream = class WritableStream {
   constructor() {
      this.locked = false;
   }
   getWriter() {
      return {
         write: () => Promise.resolve(),
         close: () => Promise.resolve(),
         abort: () => Promise.resolve(),
      };
   }
};

// Polyfill ReadableStream for MSW
global.ReadableStream = class ReadableStream {
   constructor() {
      this.locked = false;
   }
   getReader() {
      return {
         read: () => Promise.resolve({ done: true, value: undefined }),
         releaseLock: () => {},
         cancel: () => Promise.resolve(),
      };
   }
};
