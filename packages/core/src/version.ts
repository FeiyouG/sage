declare const __SAGE_VERSION__: string;
export const VERSION: string = typeof __SAGE_VERSION__ !== "undefined" ? __SAGE_VERSION__ : "dev";
