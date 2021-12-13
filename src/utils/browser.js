import uint8arrayToString from "uint8arrays/to-string";

/**
 * Convert a file to a data URL, which could then be embedded in a LIT.  A data URL is a string representation of a file.
 * @param {File} file The file to turn into a data url
 * @returns {string} The data URL.  This is a string representation that can be used anywhere the original file would be used.
 */
export function fileToDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => {
      resolve(reader.result);
    };
    reader.readAsDataURL(file);
  });
}

/**
 * Download a file in memory to the user's computer
 * @param {Object} params
 * @param {string} params.filename The name of the file
 * @param {Uint8Array} params.data The actual file itself as a Uint8Array
 * @param {string} params.mimetype The mime type of the file
 * @returns {string} The data URL.  This is a string representation that can be used anywhere the original file would be used.
 */
export function downloadFile({ filename, data, mimetype }) {
  var element = document.createElement("a");
  element.setAttribute(
    "href",
    "data:" + mimetype + ";base64," + uint8arrayToString(data, "base64")
  );
  element.setAttribute("download", filename);

  element.style.display = "none";
  document.body.appendChild(element);

  element.click();

  document.body.removeChild(element);
}

/**
 * Inject an iFrame into the current page that will display a LIT.  This function safely sandboxes the content in the iFrame so that the LIT cannot see cookies or localStorage of the parent website.
 * @param {Object} params
 * @param {Object} params.destinationId The DOM ID of the element to inject the iFrame into
 * @param {string} params.title The title of the content being displayed
 * @param {string} params.fileUrl The URL of the content that will be shown in the iFrame
 * @param {string} params.className An optional DOM class name to add to the iFrame for styling
 */
export function injectViewerIFrame({
  destinationId,
  title,
  fileUrl,
  className,
}) {
  if (fileUrl.includes("data:")) {
    // data urls are not safe, refuse to do this
    throw new Error(
      "You can not inject an iFrame with a data url.  Try a regular https URL."
    );
  }

  const url = new URL(fileUrl);
  if (url.host.toLowerCase() === window.location.host.toLowerCase()) {
    throw new Error(
      "You cannot host a LIT on the same domain as the parent webpage.  This is because iFrames with the same origin have access to localstorage and cookies in the parent webpage which is unsafe"
    );
  }

  const iframe = document.createElement("iframe");
  iframe.src = fileUrl;
  iframe.title = title;
  iframe.sandbox =
    "allow-forms allow-scripts allow-popups  allow-modals allow-popups-to-escape-sandbox allow-same-origin";
  iframe.loading = "lazy";
  iframe.allow =
    "accelerometer; ambient-light-sensor; autoplay; battery; camera; display-capture; encrypted-media; fullscreen; geolocation; gyroscope; layout-animations; legacy-image-formats; magnetometer; microphone; midi; payment; picture-in-picture; publickey-credentials-get; sync-xhr; usb; vr; screen-wake-lock; web-share; xr-spatial-tracking";
  if (className) {
    iframe.className = className;
  }
  document.getElementById(destinationId).appendChild(iframe);
}
