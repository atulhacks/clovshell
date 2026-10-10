type DockTab = 'trace' | 'flow' | 'scenarios' | 'mutations' | 'stages' | 'tools' | 'reference';
type SavedLayout = { version: 2; tab: DockTab; source: number; dock: number; inspector: boolean };

const LAYOUT_KEY = 'clovshell:layout:v2';
const TABS: { id: DockTab; label: string; key: string }[] = [
  { id: 'trace', label: 'Trace', key: '01' },
  { id: 'flow', label: 'Flow', key: '02' },
  { id: 'scenarios', label: 'Scenarios', key: '03' },
  { id: 'mutations', label: 'Mutations', key: '04' },
  { id: 'stages', label: 'Stages', key: '05' },
  { id: 'tools', label: 'Tools', key: '06' },
  { id: 'reference', label: 'Reference', key: '07' },
];

let shell: HTMLElement;
let layout: SavedLayout = { version: 2, tab: 'trace', source: 450, dock: 300, inspector: false };

function query<T extends Element = HTMLElement>(selector: string): T {
  const node = document.querySelector<T>(selector);
  if (!node) throw new Error(`Laboratory node missing: ${selector}`);
  return node;
}

function readLayout(): SavedLayout {
  try {
    const value = JSON.parse(localStorage.getItem(LAYOUT_KEY) || 'null') as Partial<SavedLayout> | null;
    if (value?.version === 2 && TABS.some((tab) => tab.id === value.tab)) {
      return {
        version: 2,
        tab: value.tab!,
        source: Number.isFinite(value.source) ? Math.max(280, Math.min(900, value.source!)) : 450,
        dock: Number.isFinite(value.dock) ? Math.max(180, Math.min(800, value.dock!)) : 300,
        inspector: value.inspector === true,
      };
    }
  } catch { /* storage may be denied or malformed */ }
  return { version: 2, tab: 'trace', source: 450, dock: 300, inspector: false };
}

function saveLayout(): void {
  try { localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout)); } catch { /* optional */ }
}

function clampLayout(): void {
  const width = shell.clientWidth;
  const height = shell.clientHeight;
  const inspectorWidth = width > 1150 ? 280 : 0;
  const sourceMax = Math.min(900, Math.max(280, width - inspectorWidth - 360));
  const dockMax = Math.min(800, Math.max(180, height - 350));
  layout.source = Math.round(Math.max(280, Math.min(layout.source, sourceMax)));
  layout.dock = Math.round(Math.max(180, Math.min(layout.dock, dockMax)));
  shell.style.setProperty('--lab-source-size', `${layout.source}px`);
  shell.style.setProperty('--lab-dock-size', `${layout.dock}px`);
  shell.classList.toggle('inspector-open', layout.inspector);
  query('#lab-inspector-toggle').setAttribute('aria-expanded', String(layout.inspector));
  const sourceSplitter = query<HTMLElement>('#lab-source-splitter');
  const dockSplitter = query<HTMLElement>('#lab-dock-splitter');
  sourceSplitter.setAttribute('aria-valuenow', String(layout.source));
  sourceSplitter.setAttribute('aria-valuemax', String(sourceMax));
  dockSplitter.setAttribute('aria-valuenow', String(layout.dock));
  dockSplitter.setAttribute('aria-valuemax', String(dockMax));
  document.dispatchEvent(new Event('lab:layout'));
}

export function activateLabTab(id: DockTab, focus = false): void {
  layout.tab = id;
  for (const tab of TABS) {
    const button = query<HTMLButtonElement>(`#lab-tab-${tab.id}`);
    const panel = query<HTMLElement>(`#lab-panel-${tab.id}`);
    const active = id === tab.id;
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
    panel.hidden = !active;
    if (active && focus) button.focus();
  }
  query<HTMLElement>('#lab-active-view').textContent = `VIEW / ${id.toUpperCase()}`;
  saveLayout();
  document.dispatchEvent(new Event('lab:layout'));
}

function configureSplitter(id: string, axis: 'x' | 'y'): void {
  const splitter = query<HTMLElement>(id);
  const set = (value: number) => {
    if (axis === 'x') layout.source = value;
    else layout.dock = value;
    clampLayout();
    saveLayout();
  };
  splitter.addEventListener('pointerdown', (event) => {
    event.preventDefault();
    splitter.setPointerCapture(event.pointerId);
    const start = axis === 'x' ? event.clientX : event.clientY;
    const initial = axis === 'x' ? layout.source : layout.dock;
    const move = (next: PointerEvent) => {
      const delta = (axis === 'x' ? next.clientX : next.clientY) - start;
      set(axis === 'x' ? initial + delta : initial - delta);
    };
    const stop = () => {
      splitter.removeEventListener('pointermove', move);
      splitter.removeEventListener('pointerup', stop);
      splitter.removeEventListener('pointercancel', stop);
    };
    splitter.addEventListener('pointermove', move);
    splitter.addEventListener('pointerup', stop);
    splitter.addEventListener('pointercancel', stop);
  });
  splitter.addEventListener('keydown', (event) => {
    const old = axis === 'x' ? layout.source : layout.dock;
    const step = event.shiftKey ? 40 : 10;
    let next = old;
    if (event.key === (axis === 'x' ? 'ArrowLeft' : 'ArrowDown')) next -= step;
    if (event.key === (axis === 'x' ? 'ArrowRight' : 'ArrowUp')) next += step;
    if (event.key === 'Home') next = axis === 'x' ? 280 : 180;
    if (event.key === 'End') next = axis === 'x' ? 900 : 800;
    if (next !== old) { event.preventDefault(); set(next); }
  });
  splitter.addEventListener('dblclick', () => set(axis === 'x' ? 450 : 300));
}

export function mountLaboratory(): void {
  const page = query<HTMLElement>('main.page');
  document.body.classList.add('lab-ready');
  const sections = [...page.querySelectorAll<HTMLElement>(':scope > section.section')];
  if (sections.length !== 9) throw new Error(`Expected nine workbench sections, found ${sections.length}`);
  const [assembly, raw, hex, disassembly, emulation, encoder, syscalls, presets, exports] = sections;
  const masthead = query<HTMLElement>('.masthead');
  const toolbar = query<HTMLElement>('.toolbar');
  const fatal = query<HTMLElement>('#fatal-msg');
  const footer = query<HTMLElement>('.footer');
  const trace = query<HTMLElement>('#trace-panel');
  const flow = query<HTMLElement>('#flow-panel');
  const mutation = query<HTMLElement>('#mutation-panel');
  const stage = query<HTMLElement>('#stage-panel');
  const scenarios = query<HTMLElement>('#scenario-panel');
  const inspectorGrid = query<HTMLElement>('.emu-grid');
  flow.remove(); mutation.remove(); stage.remove(); scenarios.remove();
  inspectorGrid.remove();

  page.innerHTML = `
    <div class="lab-shell" id="lab-shell">
      <header class="lab-command" id="lab-command">
        <div id="lab-brand-slot"></div>
        <div id="lab-toolbar-slot"></div>
        <button class="btn primary lab-run-quick" id="lab-run" type="button">▶ RUN</button>
        <button class="btn ghost hidden" id="lab-cancel-run" type="button">■ CANCEL</button>
        <button class="btn ghost lab-evidence-toggle" id="lab-evidence-toggle" type="button" aria-controls="lab-evidence" aria-expanded="false">Evidence</button>
        <button class="btn ghost lab-inspector-toggle" id="lab-inspector-toggle" type="button" aria-controls="lab-inspector" aria-expanded="false">Inspector</button>
      </header>
      <div class="lab-workspace">
        <nav class="lab-nav" aria-label="Laboratory views">
          <button type="button" data-lab-nav="build" title="Build / source">B<span>Build</span></button>
          <button type="button" data-lab-nav="analyze" title="Analyze / trace">A<span>Analyze</span></button>
          <button type="button" data-lab-nav="transform" title="Transform / tools">T<span>Transform</span></button>
          <button type="button" data-lab-nav="reference" title="Reference">R<span>Reference</span></button>
          <button type="button" id="lab-reset-layout" title="Reset pane sizes and view">↺<span>Reset layout</span></button>
        </nav>
        <div class="lab-source lab-pane" id="lab-source" aria-label="Source editor"><div class="lab-pane-label"><span>01 / SOURCE</span><span class="dim">ASSEMBLY INPUT</span></div></div>
        <div class="lab-splitter lab-splitter-vertical" id="lab-source-splitter" role="separator" tabindex="0" aria-label="Resize source and evidence panes" aria-controls="lab-source" aria-orientation="vertical" aria-valuemin="280" aria-valuemax="900"></div>
        <div class="lab-evidence lab-pane" id="lab-evidence" aria-label="Bytes and disassembly"><div class="lab-pane-label"><span>02 / EVIDENCE</span><span class="dim">BYTES → INSTRUCTIONS</span></div></div>
        <aside class="lab-inspector lab-pane" id="lab-inspector" aria-label="Execution inspector"><div class="lab-pane-label"><span>03 / INSPECTOR</span><span class="dim">RUNTIME STATE</span></div></aside>
      </div>
      <div class="lab-splitter lab-splitter-horizontal" id="lab-dock-splitter" role="separator" tabindex="0" aria-label="Resize analysis dock" aria-controls="lab-dock" aria-orientation="horizontal" aria-valuemin="180" aria-valuemax="800"></div>
      <section class="lab-dock" id="lab-dock" aria-label="Analysis dock">
        <div class="lab-dock-bar"><div class="lab-tablist" role="tablist" aria-label="Analysis views"></div><span class="lab-dock-caption">OBSERVED EVIDENCE / LOCAL SESSION</span></div>
        <div class="lab-dock-content"></div>
      </section>
      <div class="lab-status" role="status"><span class="lab-status-mark">✣</span><span>LABORATORY / LOCAL</span><span id="lab-active-view">VIEW / TRACE</span><span id="lab-run-state">NO RUN</span><span class="lab-status-right">KEYBOARD: CTRL/CMD + ENTER · ESC EXITS EDITOR</span></div>
    </div>`;
  shell = query<HTMLElement>('#lab-shell');
  query('#lab-brand-slot').append(masthead);
  query('#lab-toolbar-slot').append(toolbar);
  query('#lab-command').append(fatal);
  query('#lab-source').append(assembly!);
  query('#lab-evidence').append(raw!, hex!, disassembly!);
  query('#lab-inspector').append(emulation!);
  emulation!.querySelector('.section-head')?.after(inspectorGrid);

  for (const tab of TABS) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'lab-tab';
    button.id = `lab-tab-${tab.id}`;
    button.setAttribute('role', 'tab');
    button.setAttribute('aria-controls', `lab-panel-${tab.id}`);
    button.innerHTML = `<span class="lab-tab-key">${tab.key}</span>${tab.label}`;
    query('.lab-tablist').append(button);
    const panel = document.createElement('div');
    panel.className = 'lab-tabpanel';
    panel.id = `lab-panel-${tab.id}`;
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', button.id);
    panel.tabIndex = 0;
    query('.lab-dock-content').append(panel);
    button.addEventListener('click', () => activateLabTab(tab.id));
  }
  query('#lab-panel-trace').append(trace);
  query('#lab-panel-flow').append(flow);
  query('#lab-panel-scenarios').append(scenarios);
  query('#lab-panel-mutations').append(mutation);
  query('#lab-panel-stages').append(stage);
  query('#lab-panel-tools').append(encoder!, exports!);
  query('#lab-panel-reference').append(presets!, syscalls!, footer);
  for (const id of ['flow', 'mutations', 'stages'] as const) {
    const placeholder = document.createElement('div');
    placeholder.className = 'lab-empty-evidence';
    placeholder.textContent = `NO ${id.toUpperCase()} EVIDENCE / Run source to populate this view.`;
    query(`#lab-panel-${id}`).prepend(placeholder);
  }
  const empty = document.createElement('div');
  empty.className = 'lab-empty-trace';
  empty.textContent = 'NO EXECUTION CAPTURED / Assemble source, then press Run to inspect its instruction trace.';
  query('#lab-panel-trace').append(empty);

  const tablist = query<HTMLElement>('.lab-tablist');
  tablist.addEventListener('keydown', (event) => {
    const e = event as KeyboardEvent;
    const index = TABS.findIndex((tab) => tab.id === layout.tab);
    let next = index;
    if (e.key === 'ArrowRight') next = (index + 1) % TABS.length;
    else if (e.key === 'ArrowLeft') next = (index - 1 + TABS.length) % TABS.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = TABS.length - 1;
    else return;
    e.preventDefault();
    activateLabTab(TABS[next]!.id, true);
  });
  query('#lab-run').addEventListener('click', () => query<HTMLButtonElement>('#btn-run-emu').click());
  query('#lab-evidence-toggle').addEventListener('click', () => {
    const open = shell.classList.toggle('evidence-open');
    query('#lab-evidence-toggle').setAttribute('aria-expanded', String(open));
    document.dispatchEvent(new Event('lab:layout'));
  });
  query('#lab-inspector-toggle').addEventListener('click', () => {
    layout.inspector = !layout.inspector;
    query('#lab-inspector-toggle').setAttribute('aria-expanded', String(layout.inspector));
    clampLayout(); saveLayout();
  });
  for (const nav of document.querySelectorAll<HTMLButtonElement>('[data-lab-nav]')) {
    nav.addEventListener('click', () => {
      const view = nav.dataset.labNav;
      if (view === 'build') {
        shell.classList.remove('evidence-open');
        query('#lab-evidence-toggle').setAttribute('aria-expanded', 'false');
        query<HTMLTextAreaElement>('#asm-editor-host textarea').focus();
      }
      if (view === 'analyze') activateLabTab('trace', true);
      if (view === 'transform') activateLabTab('tools', true);
      if (view === 'reference') activateLabTab('reference', true);
    });
  }
  query('#lab-reset-layout').addEventListener('click', () => {
    layout = { version: 2, tab: 'trace', source: 450, dock: 300, inspector: false };
    query('#lab-inspector-toggle').setAttribute('aria-expanded', 'false');
    clampLayout(); activateLabTab('trace'); saveLayout();
  });
  layout = readLayout();
  configureSplitter('#lab-source-splitter', 'x');
  configureSplitter('#lab-dock-splitter', 'y');
  new ResizeObserver(() => clampLayout()).observe(shell);
  clampLayout();
  activateLabTab(layout.tab);
}

export function setLabEvidenceReady(ready: boolean): void {
  for (const placeholder of document.querySelectorAll<HTMLElement>('.lab-empty-evidence')) {
    placeholder.hidden = ready;
  }
}
