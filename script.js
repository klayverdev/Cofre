(() => {
  const KDF_ITERATIONS = 600000;
  const VAULT_FILENAME = 'vault.json';

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0));

  let state = {
    entries: [],
    masterKeyMaterial: null, // raw password bytes, re-derived per save with fresh salt
    editingId: null,
    loadedFromFile: false,
  };

  // ---------- crypto ----------
  async function deriveKey(password, salt) {
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: KDF_ITERATIONS, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptVault(password, entries) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const plaintext = enc.encode(JSON.stringify(entries));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    return {
      v: 1,
      kdf: 'PBKDF2-SHA256',
      iterations: KDF_ITERATIONS,
      salt: b64(salt),
      iv: b64(iv),
      ciphertext: b64(ciphertext),
    };
  }

  async function decryptVault(password, file) {
    const salt = unb64(file.salt);
    const iv = unb64(file.iv);
    const ciphertext = unb64(file.ciphertext);
    const key = await deriveKey(password, salt);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(dec.decode(plaintext));
  }

  // ---------- gate ----------
  const gateTitle = document.getElementById('gate-title');
  const gateSub = document.getElementById('gate-sub');
  const gateMsg = document.getElementById('gate-msg');
  const pw1 = document.getElementById('pw1');
  const pw2Field = document.getElementById('pw2-field');
  const pw2 = document.getElementById('pw2');
  const gateSubmit = document.getElementById('gate-submit');
  const switchMode = document.getElementById('switch-mode');
  const filepick = document.getElementById('filepick');
  const fileInput = document.getElementById('file-input');

  let mode = 'unlock'; // 'unlock' | 'create'
  let loadedFile = null; // encrypted json object currently targeted for unlock

  function showMsg(text, kind) {
    gateMsg.innerHTML = text ? `<div class="msg ${kind}">${text}</div>` : '';
  }

  function setMode(next) {
    mode = next;
    pw2Field.style.display = mode === 'create' ? 'block' : 'none';
    if (mode === 'create') {
      gateTitle.textContent = 'Criar cofre';
      gateSub.textContent = 'Nenhum cofre foi encontrado neste diretório. Defina uma senha mestra forte — ela não pode ser recuperada se você a perder.';
      gateSubmit.textContent = 'Criar cofre';
      switchMode.innerHTML = 'Já tem um arquivo de cofre? <button id="to-unlock">Carregar em vez disso</button>';
      document.getElementById('to-unlock').onclick = () => { setMode('unlock'); showMsg('', ''); };
    } else {
      gateTitle.textContent = 'Abrir cofre';
      gateSub.textContent = loadedFile
        ? 'Digite a senha mestra para descriptografar o cofre carregado deste repositório.'
        : 'Nenhum vault.json encontrado automaticamente. Escolha um arquivo abaixo ou crie um novo cofre.';
      gateSubmit.textContent = 'Abrir';
      switchMode.innerHTML = 'Ainda não tem um cofre? <button id="to-create">Criar um novo</button>';
      document.getElementById('to-create').onclick = () => { setMode('create'); showMsg('', ''); };
    }
  }

  async function tryAutoload() {
    try {
      const res = await fetch(VAULT_FILENAME, { cache: 'no-store' });
      if (res.ok) {
        loadedFile = await res.json();
        state.loadedFromFile = true;
        setMode('unlock');
        return;
      }
    } catch (e) { /* fine, likely local file:// or not created yet */ }
    setMode('create');
  }

  fileInput.addEventListener('change', async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    try {
      loadedFile = JSON.parse(await f.text());
      state.loadedFromFile = true;
      setMode('unlock');
      showMsg('Arquivo carregado. Digite a senha mestra.', 'ok');
    } catch (err) {
      showMsg('Não foi possível ler esse arquivo como JSON válido.', 'error');
    }
  });

  gateSubmit.addEventListener('click', async () => {
    const p1 = pw1.value;
    if (!p1) { showMsg('Digite a senha mestra.', 'error'); return; }

    if (mode === 'create') {
      const p2 = pw2.value;
      if (p1.length < 8) { showMsg('Use pelo menos 8 caracteres — de preferência bem mais.', 'error'); return; }
      if (p1 !== p2) { showMsg('As senhas não coincidem.', 'error'); return; }
      state.entries = [];
      state.password = p1;
      openVault();
      return;
    }

    if (!loadedFile) { showMsg('Escolha um arquivo de cofre primeiro.', 'error'); return; }
    gateSubmit.disabled = true;
    gateSubmit.textContent = 'Descriptografando…';
    try {
      const entries = await decryptVault(p1, loadedFile);
      state.entries = entries;
      state.password = p1;
      openVault();
    } catch (err) {
      showMsg('Senha incorreta ou arquivo corrompido.', 'error');
      gateSubmit.disabled = false;
      gateSubmit.textContent = 'Abrir';
    }
  });

  [pw1, pw2].forEach(el => el.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') gateSubmit.click();
  }));

  // ---------- vault view ----------
  const gateEl = document.getElementById('gate');
  const vaultEl = document.getElementById('vault');
  const entriesEl = document.getElementById('entries');
  const emptyState = document.getElementById('empty-state');
  const searchEl = document.getElementById('search');
  const editorSlot = document.getElementById('editor-slot');
  const addBtn = document.getElementById('add-btn');
  const saveBtn = document.getElementById('save-btn');
  const lockBtn = document.getElementById('lock-btn');

  function openVault() {
    gateEl.style.display = 'none';
    vaultEl.style.display = 'block';
    pw1.value = ''; pw2.value = '';
    render();
  }

  function lockVault() {
    state.password = null;
    state.entries = [];
    state.editingId = null;
    editorSlot.innerHTML = '';
    vaultEl.style.display = 'none';
    gateEl.style.display = 'block';
    showMsg('', '');
    setMode(loadedFile ? 'unlock' : 'create');
  }
  lockBtn.addEventListener('click', lockVault);

  function uid() { return crypto.randomUUID(); }

  function genPassword(len = 20) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+';
    const arr = crypto.getRandomValues(new Uint32Array(len));
    return Array.from(arr, n => chars[n % chars.length]).join('');
  }

  function render() {
    const q = searchEl.value.trim().toLowerCase();
    const filtered = state.entries.filter(e =>
      !q || e.site.toLowerCase().includes(q) || (e.username || '').toLowerCase().includes(q)
    );

    entriesEl.innerHTML = '';
    emptyState.style.display = filtered.length === 0 ? 'block' : 'none';

    filtered.forEach(entry => {
      const li = document.createElement('li');
      li.className = 'entry';
      li.innerHTML = `
        <div>
          <div class="site">${escapeHtml(entry.site)}</div>
          <div class="user mono">${escapeHtml(entry.username || '—')}</div>
        </div>
        <div class="row-btns">
          <button data-act="edit">editar</button>
          <button data-act="del">remover</button>
        </div>
        <div class="pw-line">
          <span class="pw mono" data-role="pw">${'•'.repeat(Math.min(entry.password.length, 24))}</span>
          <button class="icon-btn" data-act="reveal">mostrar</button>
          <button class="icon-btn" data-act="copy">copiar</button>
        </div>
        ${entry.notes ? `<div class="notes">${escapeHtml(entry.notes)}</div>` : ''}
      `;
      li.querySelector('[data-act="reveal"]').addEventListener('click', (e) => {
        const span = li.querySelector('[data-role="pw"]');
        const btn = e.currentTarget;
        const shown = btn.dataset.shown === '1';
        span.textContent = shown ? '•'.repeat(Math.min(entry.password.length, 24)) : entry.password;
        btn.textContent = shown ? 'mostrar' : 'ocultar';
        btn.dataset.shown = shown ? '0' : '1';
      });
      li.querySelector('[data-act="copy"]').addEventListener('click', async (e) => {
        await navigator.clipboard.writeText(entry.password);
        const btn = e.currentTarget;
        const old = btn.textContent;
        btn.textContent = 'copiado';
        setTimeout(() => btn.textContent = old, 1200);
      });
      li.querySelector('[data-act="edit"]').addEventListener('click', () => openEditor(entry.id));
      li.querySelector('[data-act="del"]').addEventListener('click', () => {
        if (confirm(`Remover a senha de "${entry.site}"?`)) {
          state.entries = state.entries.filter(x => x.id !== entry.id);
          render();
        }
      });
      entriesEl.appendChild(li);
    });
  }

  function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  function openEditor(id) {
    state.editingId = id;
    const entry = id ? state.entries.find(e => e.id === id) : { site: '', username: '', password: '', notes: '' };

    editorSlot.innerHTML = `
      <div class="editor">
        <h2>${id ? 'Editar senha' : 'Nova senha'}</h2>
        <div class="field">
          <label>Site ou serviço</label>
          <input type="text" id="f-site" value="${escapeHtml(entry.site)}" placeholder="ex: github.com">
        </div>
        <div class="field">
          <label>Usuário / e-mail</label>
          <input type="text" id="f-user" value="${escapeHtml(entry.username || '')}" autocomplete="off">
        </div>
        <div class="field">
          <label>Senha</label>
          <div class="genrow">
            <input type="text" id="f-pass" class="mono" value="${escapeHtml(entry.password || '')}" autocomplete="off" spellcheck="false">
            <button class="btn" id="f-gen" type="button">gerar</button>
          </div>
        </div>
        <div class="field">
          <label>Notas (opcional)</label>
          <textarea id="f-notes">${escapeHtml(entry.notes || '')}</textarea>
        </div>
        <div class="row-actions">
          <button class="btn primary" id="f-save">Salvar entrada</button>
          <button class="btn ghost" id="f-cancel">Cancelar</button>
        </div>
      </div>
    `;

    document.getElementById('f-gen').addEventListener('click', () => {
      document.getElementById('f-pass').value = genPassword(20);
    });
    document.getElementById('f-cancel').addEventListener('click', () => {
      editorSlot.innerHTML = '';
      state.editingId = null;
    });
    document.getElementById('f-save').addEventListener('click', () => {
      const site = document.getElementById('f-site').value.trim();
      const username = document.getElementById('f-user').value.trim();
      const password = document.getElementById('f-pass').value;
      const notes = document.getElementById('f-notes').value.trim();
      if (!site || !password) {
        alert('Preencha ao menos o site e a senha.');
        return;
      }
      if (id) {
        const e2 = state.entries.find(e => e.id === id);
        Object.assign(e2, { site, username, password, notes });
      } else {
        state.entries.push({ id: uid(), site, username, password, notes });
      }
      editorSlot.innerHTML = '';
      state.editingId = null;
      render();
    });
  }

  addBtn.addEventListener('click', () => openEditor(null));
  searchEl.addEventListener('input', render);

  saveBtn.addEventListener('click', async () => {
    saveBtn.disabled = true;
    saveBtn.textContent = 'Criptografando…';
    try {
      const file = await encryptVault(state.password, state.entries);
      const blob = new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = VAULT_FILENAME;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = 'Baixar cofre atualizado';
    }
  });

  // boot
  tryAutoload();
})();
