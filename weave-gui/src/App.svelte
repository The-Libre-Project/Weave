<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";

  // App list state
  let apps = $state<string[]>([]);
  let error = $state("");
  let launching = $state("");

  // Create form state
  let newName = $state("");
  let newExePath = $state("");
  let creating = $state(false);

  async function loadApps() {
    try {
      apps = await invoke<string[]>("list_apps");
      error = "";
    } catch (e) {
      error = String(e);
    }
  }

  async function createPrefix() {
    if (!newName.trim()) return;
    creating = true;
    try {
      await invoke("create_prefix", {
        name: newName.trim(),
        exePath: newExePath.trim(),
      });
      newName = "";
      newExePath = "";
      error = "";
      await loadApps();
    } catch (e) {
      error = String(e);
    } finally {
      creating = false;
    }
  }

  async function deletePrefix(name: string) {
    try {
      await invoke("delete_prefix", { name });
      error = "";
      await loadApps();
    } catch (e) {
      error = String(e);
    }
  }

  async function launchApp(name: string) {
    launching = name;
    try {
      await invoke("launch_app", { prefixName: name });
      error = "";
    } catch (e) {
      error = String(e);
    } finally {
      launching = "";
    }
  }
</script>

<main>
  <header>
    <h1>Weave</h1>
    <p class="subtitle">Windows application manager</p>
  </header>

  <section class="create-form">
    <h2>Add application</h2>
    <div class="form-row">
      <input
        type="text"
        placeholder="Prefix name (e.g. notepad)"
        bind:value={newName}
      />
      <input
        type="text"
        placeholder="Exe path (e.g. C:\App\app.exe)"
        bind:value={newExePath}
      />
      <button onclick={createPrefix} disabled={creating || !newName.trim()}>
        {creating ? "Creating…" : "Add"}
      </button>
    </div>
  </section>

  <section class="app-list">
    <div class="list-header">
      <h2>Applications ({apps.length})</h2>
      <button class="refresh" onclick={loadApps}>Refresh</button>
    </div>

    {#if apps.length === 0}
      <p class="empty">No applications yet. Add one above.</p>
    {:else}
      <ul>
        {#each apps as app}
          <li>
            <span class="app-name">{app}</span>
            <div class="actions">
              <button
                onclick={() => launchApp(app)}
                disabled={launching === app}
                class="launch"
              >
                {launching === app ? "Launching…" : "Launch"}
              </button>
              <button onclick={() => deletePrefix(app)} class="delete">
                Remove
              </button>
            </div>
          </li>
        {/each}
      </ul>
    {/if}

    {#if error}
      <p class="error">{error}</p>
    {/if}
  </section>
</main>

<style>
  main {
    padding: 2rem;
    max-width: 860px;
    margin: 0 auto;
  }

  header {
    margin-bottom: 2rem;
  }

  h1 {
    font-size: 2rem;
    font-weight: 700;
  }

  .subtitle {
    color: #888;
    margin-top: 0.25rem;
  }

  h2 {
    font-size: 1.1rem;
    margin-bottom: 1rem;
  }

  .create-form {
    margin-bottom: 2rem;
    padding: 1.25rem;
    background: #222;
    border-radius: 6px;
    border: 1px solid #333;
  }

  .form-row {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  input {
    flex: 1;
    min-width: 160px;
    padding: 0.4rem 0.6rem;
    background: #1a1a1a;
    border: 1px solid #444;
    color: inherit;
    border-radius: 4px;
    font-size: 0.9rem;
  }

  input::placeholder {
    color: #555;
  }

  .list-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
  }

  .list-header h2 {
    margin-bottom: 0;
  }

  .app-list ul {
    list-style: none;
  }

  .app-list li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.6rem 0;
    border-bottom: 1px solid #2a2a2a;
  }

  .app-name {
    font-size: 0.95rem;
  }

  .actions {
    display: flex;
    gap: 0.4rem;
  }

  .empty {
    color: #555;
    font-size: 0.9rem;
  }

  button {
    padding: 0.4rem 0.9rem;
    cursor: pointer;
    background: #2e2e2e;
    border: 1px solid #444;
    color: inherit;
    border-radius: 4px;
    font-size: 0.9rem;
  }

  button:hover:not(:disabled) {
    background: #3e3e3e;
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  button.launch {
    background: #1a3a1a;
    border-color: #2a5a2a;
  }

  button.launch:hover:not(:disabled) {
    background: #1f4a1f;
  }

  button.delete {
    background: #3a1a1a;
    border-color: #5a2a2a;
    font-size: 0.8rem;
  }

  button.delete:hover {
    background: #4a1a1a;
  }

  button.refresh {
    font-size: 0.8rem;
    padding: 0.25rem 0.6rem;
  }

  .error {
    color: #ff6b6b;
    margin-top: 0.75rem;
    font-size: 0.9rem;
  }
</style>
