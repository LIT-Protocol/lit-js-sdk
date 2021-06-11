import { sendMessageToFrameParent } from './frameComms'
import LitNodeClient from './litNodeClient'

export const litJsSdkLoadedInALIT = () => {
  sendMessageToFrameParent({ command: 'LIT_SYN' }, '*')
  setTimeout(function () {
    if (!window.useLitPostMessageProxy) {
      console.log('inside lit - no parent frame lit node connection.  connecting ourselves.')
      // we're on our own with no parent frame.  initiate our own connection to lit nodes
      const litNodeClient = new LitNodeClient()
      litNodeClient.connect()
      window.litNodeClient = litNodeClient
    } else {
      console.log('inside lit - parent frame is connected to lit nodes.  using that.')
    }
  }, 1000)
}
