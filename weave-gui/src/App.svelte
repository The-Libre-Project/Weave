<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";

  let appCount = $state(0);
  let apps = $state<string[]>([]);
  let error = $state("");
  let launching = $state(false);

  async function loadApps() {
    try {
      appCount = await invoke<number>("count_apps");
      apps = await invoke<string[]>("list_apps");
      error = "";
    } catch (e) {
      error = String(e);
    }
  }

  async function launchApp(name: string) {
    launching = true;
    try {
      await invoke("launch_app", { prefixName: name });
      error = "";
    } catch (e) {
      error = String(e);
    } finally {
      launching = false;
    }
  }
</script>

<main>
  <header>
    <h1>Weave</h1>
    <p class="subtitle">Windows application manager</p>
  </header>

  <section class="controls">
    <button onclick={loadApps}>Refresh</button>
  </section>

  <section class="app-list">
    <h2>Applications ({appCount})</h2>
    {#if apps.length === 0}
      <p class="empty">No applications installed yet.</p>
    {:else}
      <ul>
        {#each apps as app}
          <li>
            <span>{app}</span>
            <button onclick={() => launchApp(app)} disabled={launching}>
              {launching ? "Launching…" : "Launch"}
            </button>
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

  .controls {
    margin-bottom: 1.5rem;
  }

  .app-list ul {
    list-style: none;
  }

  .app-list li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.6rem 0;
    border-bottom: 1px solid #333;
  }

  .empty {
    color: #666;
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

  .error {
    color: #ff6b6b;
    margin-top: 0.75rem;
    font-size: 0.9rem;
  }
</style>