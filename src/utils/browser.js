/**
 * Convert a file to a data URL, which could then be embedded in a LIT.  A data URL is a string representation of a file.
 * @param {File} file The file to turn into a data url
 * @returns {string} The data URL.  This is a string representation that can be used anywhere the original file would be used.
 */
export function fileToDataUrl (file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onloadend = () => {
      resolve(reader.result)
    }
    reader.readAsDataURL(file)
  })
}

/**
 * Inject an iFrame into the current page that will display a LIT.  This function safely sandboxes the content in the iFrame so that the LIT cannot see cookies or localStorage of the parent website.
 * @param {Object} params
 * @param {Object} params.symmetricKey The decryption key obtained by calling "LitNodeClient.getEncryptionKey"
 * @returns {promise} A promise that will resolve when the LIT is unlocked
 */
export function injectViewerIFrame ({ destinationId, title, fileUrl, className }) {
  if (fileUrl.includes('data:')) {
    // data urls are not safe, refuse to do this
    throw new Error('You can not inject an iFrame with a data url.  Try a regular https URL.')
  }

  const url = new URL(fileUrl)
  if (url.host.toLowerCase() === window.location.host.toLowerCase()) {
    throw new Error('You cannot host a LIT on the same domain as the parent webpage.  This is because iFrames with the same origin have access to localstorage and cookies in the parent webpage which is unsafe')
  }

  const iframe = document.createElement('iframe')
  iframe.src = fileUrl
  iframe.title = title
  iframe.sandbox = 'allow-forms allow-scripts allow-popups  allow-modals allow-popups-to-escape-sandbox allow-same-origin'
  iframe.loading = 'lazy'
  iframe.allow = 'accelerometer; ambient-light-sensor; autoplay; battery; camera; display-capture; encrypted-media; fullscreen; geolocation; gyroscope; layout-animations; legacy-image-formats; magnetometer; microphone; midi; payment; picture-in-picture; publickey-credentials-get; sync-xhr; usb; vr; screen-wake-lock; web-share; xr-spatial-tracking'
  if (className) {
    iframe.className = className
  }
  document.getElementById(destinationId).appendChild(iframe)
}
