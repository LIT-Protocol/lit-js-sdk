declare function _exports(idsOption: any, options: any): {
    setSizes: (newSizes: any) => void;
    destroy: (preserveStyles: any, preserveGutter: any) => void;
    getSizes?: undefined;
    collapse?: undefined;
    parent?: undefined;
    pairs?: undefined;
} | {
    setSizes: (newSizes: any) => void;
    getSizes: () => any;
    collapse: (i: any) => void;
    destroy: (preserveStyles: any, preserveGutter: any) => void;
    parent: any;
    pairs: any[];
};
export = _exports;
