/**
 * IDE Integration Types
 * Consolidated from tabby-chat-panel for web-first architecture
 */

export const TABBY_CHAT_PANEL_API_VERSION = '0.10.0'

/**
 * Represents a position in a file.
 */
export interface Position {
  line: number
  character: number
}

/**
 * Represents a range in a file.
 */
export interface PositionRange {
  start: Position
  end: Position
}

/**
 * Represents a range of lines in a file.
 */
export interface LineRange {
  start: number
  end: number
}

export type Location = number | LineRange | Position | PositionRange

export interface FilepathInGitRepository {
  kind: 'git'
  filepath: string
  gitUrl: string
  revision?: string
}

export interface FilepathInWorkspace {
  kind: 'workspace'
  filepath: string
  baseDir: string
}

export interface FilepathUri {
  kind: 'uri'
  uri: string
}

export type Filepath = FilepathInGitRepository | FilepathInWorkspace | FilepathUri

export interface EditorFileContext {
  kind: 'file'
  filepath: Filepath
  range?: LineRange | PositionRange
  content: string
}

export interface TerminalContext {
  kind: 'terminal'
  name: string
  processId: number | undefined
  selection: string
}

export type EditorContext = EditorFileContext | TerminalContext

export interface FileLocation {
  filepath: Filepath
  location?: Location
}

export interface FileRange {
  filepath: Filepath
  range?: LineRange | PositionRange
}

export interface GitRepository {
  url: string
}

// Server API Types
export type ChatCommand = 'explain' | 'fix' | 'generate-docs' | 'generate-tests' | 'code-review' | 'explain-terminal'
export type ChatView = 'new-chat' | 'history'

export interface InitRequest {
  fetcherOptions: {
    authorization: string
    headers?: Record<string, unknown>
  }
  useMacOSKeyboardEventHandler?: boolean
}

export interface ErrorMessage {
  title?: string
  content: string
}

// Client API Types
export interface OnLoadedParams {
  apiVersion: string
}

export interface ApplyInEditorOptions {
  languageId?: string
  smart?: boolean
}

export interface LookupSymbolHint {
  filepath?: Filepath
  location?: Location
}

export interface SymbolInfo {
  source: FileLocation
  target: FileLocation
}

export interface ListFilesInWorkspaceParams {
  query: string
  limit?: number
}

export interface ListFileItem {
  filepath: Filepath
  source?: 'openedInEditor' | 'searchResult'
}

export interface ListSymbolsParams {
  query: string
  limit?: number
}

export interface ListSymbolItem {
  label: string
  filepath: Filepath
  range: LineRange
}

export interface GetChangesParams {
  maxChars?: number
}

export interface ChangeItem {
  content: string
  staged: boolean
}

// Client API Interface
export interface ClientApi {
  onLoaded?: (params?: OnLoadedParams | undefined) => Promise<void>
  refresh: () => Promise<void>
  openInEditor: (target: FileLocation) => Promise<boolean>
  openExternal: (url: string) => Promise<void>
  getActiveEditorSelection: () => Promise<EditorFileContext | null>
  getActiveTerminalSelection?: () => Promise<TerminalContext | null>
  onCopy: (content: string) => Promise<void>
  onApplyInEditor: (content: string) => Promise<void>
  onApplyInEditorV2?: (content: string, options?: ApplyInEditorOptions) => Promise<void>
  onKeyboardEvent?: (type: 'keydown' | 'keyup' | 'keypress', event: KeyboardEventInit) => Promise<void>
  readWorkspaceGitRepositories?: () => Promise<GitRepository[]>
  readFileContent?: (fileRange: FileRange) => Promise<string | null>
  listFileInWorkspace?: (params: ListFilesInWorkspaceParams) => Promise<ListFileItem[]>
  listSymbols?: (params: ListSymbolsParams) => Promise<ListSymbolItem[]>
  lookupSymbol?: (symbol: string, hints?: LookupSymbolHint[] | undefined) => Promise<SymbolInfo | null>
  fetchSessionState?: (keys?: string[] | undefined) => Promise<Record<string, unknown> | null>
  storeSessionState?: (state: Record<string, unknown>) => Promise<void>
  getChanges?: (params: GetChangesParams) => Promise<ChangeItem[]>
  runShell?: (command: string) => Promise<void>
}

// Server API Interface
export interface ServerApi {
  init: (request: InitRequest) => Promise<void>
  showError: (error: ErrorMessage) => Promise<void>
  cleanError: () => Promise<void>
  updateTheme: (style: string, themeClass: 'dark' | 'light') => Promise<void>
  executeCommand: (command: ChatCommand) => Promise<void>
  navigate: (view: ChatView) => Promise<void>
  addRelevantContext: (context: EditorContext) => Promise<void>
  updateActiveSelection: (selection: EditorContext | undefined | null) => Promise<void>
  getVersion: () => Promise<string>
}
