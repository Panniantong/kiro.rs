const API_KEY_STORAGE_KEY = 'adminApiKey'
const CREDENTIAL_VIEW_STORAGE_KEY = 'credentialViewMode'

export const storage = {
  getApiKey: () => localStorage.getItem(API_KEY_STORAGE_KEY),
  setApiKey: (key: string) => localStorage.setItem(API_KEY_STORAGE_KEY, key),
  removeApiKey: () => localStorage.removeItem(API_KEY_STORAGE_KEY),
  getCredentialView: () => localStorage.getItem(CREDENTIAL_VIEW_STORAGE_KEY),
  setCredentialView: (view: string) => localStorage.setItem(CREDENTIAL_VIEW_STORAGE_KEY, view),
}
