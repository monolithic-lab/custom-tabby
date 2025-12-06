import { useEffect, useState } from 'react'
import type { ClientApi, ServerApi } from './types'

/**
 * Hook for server-side (inside iframe) to communicate with IDE client
 */
export function useServer(api: ServerApi): ClientApi | null {
  const [server, setServer] = useState<ClientApi | null>(null)
  
  useEffect(() => {
    const isInIframe = window.self !== window.top
    if (!isInIframe) return

    // Set up postMessage communication with parent window
    const handleMessage = (event: MessageEvent) => {
      if (event.data?.type === 'tabby-client-ready') {
        // Create proxy to parent window
        const clientProxy = createClientProxy()
        setServer(clientProxy)
      }
      
      if (event.data?.type === 'tabby-client-call') {
        const { method, args, callId } = event.data
        const fn = api[method as keyof ServerApi]
        if (typeof fn === 'function') {
          Promise.resolve((fn as Function)(...args))
            .then(result => {
              window.parent.postMessage({
                type: 'tabby-server-response',
                callId,
                result
              }, '*')
            })
            .catch(error => {
              window.parent.postMessage({
                type: 'tabby-server-response',
                callId,
                error: error.message
              }, '*')
            })
        }
      }
    }

    window.addEventListener('message', handleMessage)
    
    // Notify parent that server is ready
    window.parent.postMessage({ type: 'tabby-server-ready', methods: Object.keys(api) }, '*')

    return () => {
      window.removeEventListener('message', handleMessage)
    }
  }, [api])

  return server
}

function createClientProxy(): ClientApi {
  let callId = 0
  const pendingCalls = new Map<number, { resolve: Function; reject: Function }>()

  const handleResponse = (event: MessageEvent) => {
    if (event.data?.type === 'tabby-client-response') {
      const { callId: id, result, error } = event.data
      const pending = pendingCalls.get(id)
      if (pending) {
        pendingCalls.delete(id)
        if (error) {
          pending.reject(new Error(error))
        } else {
          pending.resolve(result)
        }
      }
    }
  }

  window.addEventListener('message', handleResponse)

  const createMethod = (method: string) => {
    return (...args: any[]) => {
      return new Promise((resolve, reject) => {
        const id = callId++
        pendingCalls.set(id, { resolve, reject })
        window.parent.postMessage({
          type: 'tabby-server-call',
          method,
          args,
          callId: id
        }, '*')
      })
    }
  }

  // Create proxy with all client methods
  return {
    onLoaded: createMethod('onLoaded'),
    refresh: createMethod('refresh'),
    openInEditor: createMethod('openInEditor'),
    openExternal: createMethod('openExternal'),
    getActiveEditorSelection: createMethod('getActiveEditorSelection'),
    getActiveTerminalSelection: createMethod('getActiveTerminalSelection'),
    onCopy: createMethod('onCopy'),
    onApplyInEditor: createMethod('onApplyInEditor'),
    onApplyInEditorV2: createMethod('onApplyInEditorV2'),
    onKeyboardEvent: createMethod('onKeyboardEvent'),
    readWorkspaceGitRepositories: createMethod('readWorkspaceGitRepositories'),
    readFileContent: createMethod('readFileContent'),
    listFileInWorkspace: createMethod('listFileInWorkspace'),
    listSymbols: createMethod('listSymbols'),
    lookupSymbol: createMethod('lookupSymbol'),
    fetchSessionState: createMethod('fetchSessionState'),
    storeSessionState: createMethod('storeSessionState'),
    getChanges: createMethod('getChanges'),
    runShell: createMethod('runShell')
  } as ClientApi
}
