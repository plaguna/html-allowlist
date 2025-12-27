const settings = (globalThis as { happyDOM?: { settings?: Record<string, boolean> } }).happyDOM?.settings;

if (settings) {
  settings.disableJavaScriptEvaluation = true;
  settings.disableJavaScriptFileLoading = true;
  settings.disableCSSFileLoading = true;
  settings.disableIframePageLoading = true;
  settings.handleDisabledFileLoadingAsSuccess = true;
}
