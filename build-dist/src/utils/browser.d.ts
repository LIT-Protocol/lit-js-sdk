import Blob from "cross-blob";
/** Convert a Blob to a base64urlpad string.  Note: This function returns a promise.
 * @param {Blob | File} blob The Blob or File to turn into a base64 string
 * @returns {Promise<String>} A promise that resolves to the base64 string
 */
export declare function blobToBase64String(blob: any): Promise<string>;
/** Convert a base64urlpad string to a Blob.  Note: This function DOES NOT return a promise
 * @param {String} base64String The base64 string that to turn into a Blob
 * @returns {Blob}  A blob that contains the decoded base64 data
 */
export declare function base64StringToBlob(base64String: any): Blob;
/** Convert a Uint8Array to a string.  Supports various encodings.  This is a re-export of https://www.npmjs.com/package/uint8arrays and you can find the list of supported encodings here https://github.com/multiformats/multibase/blob/master/multibase.csv
 * @param {Uint8Array} uint8array The Uint8Array to convert to a string
 * @param {String} encoding The encoding to use when converting the Uint8Array to a string.
 * @returns {String} The string representation of the Uint8Array
 */
export declare function uint8arrayToString(uint8array: any, encoding: any): string;
/** Convert a string to a Uint8Array.  Supports various encodings.  This is a re-export of https://www.npmjs.com/package/uint8arrays and you can find the list of supported encodings here https://github.com/multiformats/multibase/blob/master/multibase.csv
 * @param {String} str The string to convert to a Uint8Array
 * @param {String} encoding The encoding to use when converting the string to a Uint8Array.
 * @returns {String} The Uint8Array representation of the data from the string
 */
export declare function uint8arrayFromString(str: any, encoding: any): Uint8Array;
/**
 * Convert a file to a data URL, which could then be embedded in a LIT.  A data URL is a string representation of a file.
 * @param {File} file The file to turn into a data url
 * @returns {string} The data URL.  This is a string representation that can be used anywhere the original file would be used.
 */
export declare function fileToDataUrl(file: any): Promise<unknown>;
/**
 * Download a file in memory to the user's computer
 * @param {Object} params
 * @param {string} params.filename The name of the file
 * @param {Uint8Array} params.data The actual file itself as a Uint8Array
 * @param {string} params.mimetype The mime type of the file
 * @returns {string} The data URL.  This is a string representation that can be used anywhere the original file would be used.
 */
export declare function downloadFile({ filename, data, mimetype }: any): void;
/**
 * Inject an iFrame into the current page that will display a LIT.  This function safely sandboxes the content in the iFrame so that the LIT cannot see cookies or localStorage of the parent website.
 * @param {Object} params
 * @param {Object} params.destinationId The DOM ID of the element to inject the iFrame into
 * @param {string} params.title The title of the content being displayed
 * @param {string} params.fileUrl The URL of the content that will be shown in the iFrame
 * @param {string} params.className An optional DOM class name to add to the iFrame for styling
 */
export declare function injectViewerIFrame({ destinationId, title, fileUrl, className }: any): void;
