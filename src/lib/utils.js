export const printError = (e) => {
  console.log("Error Stack", e.stack);
  console.log("Error Name", e.name);
  console.log("Error Message", e.message);
};

export const mostCommonString = (arr) => {
  return arr
    .sort(
      (a, b) =>
        arr.filter((v) => v === a).length - arr.filter((v) => v === b).length
    )
    .pop();
};

export const throwError = ({ message, name, errorCode }) => {
  throw new (function () {
    this.message = message;
    this.name = name;
    this.errorCode = errorCode;
  })();
};

export const log = (...args) => {
  if (
    globalThis &&
    globalThis.litConfig &&
    globalThis.litConfig.debug === false
  ) {
    return;
  }
  args.unshift("[Lit-JS-SDK]");
  console.log(...args);
};

/**
 * 
 * Get the type of a variable, could be an object instance type. 
 * eg Uint8Array instance should return 'Uint8Array` as string
 * or simply a `string` or `int` type
 * 
 * @param { * } value 
 * @returns { String } type
 */
export const getVarType = (value) => {

  // if it's an object
  if(value instanceof Object){
      if(value.constructor.name == 'Object'){
          return 'Object';
      }
      return value.constructor.name;
  }

  // if it's other type, like string and int
  return typeof value;
}