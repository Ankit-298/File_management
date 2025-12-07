

// Sample file data (will be persisted to localStorage when modified)
let files = [
    { id: 1, name: "Financial_Report.pdf", type: "pdf", size: "2.4 MB", date: "2023-10-15", encrypted: true, originalExt: "pdf", originalMime: "application/pdf", permissions: { view: true, download: true, edit: false, canDelete: false } },
    { id: 2, name: "Project_Proposal.docx", type: "docx", size: "1.8 MB", date: "2023-10-14", encrypted: true, originalExt: "docx", originalMime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", permissions: { view: true, download: true, edit: true, canDelete: false } },
    { id: 3, name: "Q3_Data_Analysis.xlsx", type: "xlsx", size: "3.2 MB", date: "2023-10-12", encrypted: true, originalExt: "xlsx", originalMime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", permissions: { view: true, download: false, edit: true, canDelete: true } },
    { id: 4, name: "Company_Presentation.pptx", type: "pptx", size: "5.1 MB", date: "2023-10-10", encrypted: false, originalExt: "pptx", originalMime: "application/vnd.openxmlformats-officedocument.presentationml.presentation", permissions: { view: true, download: true, edit: true, canDelete: true } },
    { id: 5, name: "Team_Photo.jpg", type: "img", size: "4.5 MB", date: "2023-10-08", encrypted: true, originalExt: "jpg", originalMime: "image/jpeg", permissions: { view: true, download: true, edit: true, canDelete: true } },
    { id: 6, name: "Backup_Archive.zip", type: "zip", size: "12.7 MB", date: "2023-10-05", encrypted: true, originalExt: "zip", originalMime: "application/zip", permissions: { view: false, download: true, edit: false, canDelete: true } },
    { id: 7, name: "Security_Audit.pdf", type: "pdf", size: "3.8 MB", date: "2023-10-03", encrypted: true, originalExt: "pdf", originalMime: "application/pdf", permissions: { view: true, download: true, edit: true, canDelete: false } },
    { id: 8, name: "Meeting_Notes.txt", type: "txt", size: "0.2 MB", date: "2023-10-01", encrypted: false, originalExt: "txt", originalMime: "text/plain", permissions: { view: true, download: true, edit: true, canDelete: true } }
];

// Recycle bin / trash (soft-deleted files)
let trash = [];

// Session inactivity / auto-lock settings
const INACTIVITY_MS = 5 * 60 * 1000; // 5 minutes
let inactivityTimer = null;

// Auto-clean interval for trash (runs every minute)
const TRASH_CLEAN_INTERVAL_MS = 60 * 1000;
let trashCleanerInterval = null;

// Persistence helpers
function filesStorageKey() { return 'secure_files_store_v1'; }
function saveFilesToStorage() {
    try {
        localStorage.setItem(filesStorageKey(), JSON.stringify(files));
        // persist trash too
        try { localStorage.setItem(trashStorageKey(), JSON.stringify(trash)); } catch (e) { }
        try { updateDashboardStats(); } catch (e) { }
        try { updateTrashBadge(); } catch (e) { }
    } catch (e) { }
}

function loadFilesFromStorage() {
    try {
        const raw = localStorage.getItem(filesStorageKey());
        if (raw) {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed)) files = parsed;
        }
        // load trash as well
        const traw = localStorage.getItem(trashStorageKey());
        if (traw) {
            const tparsed = JSON.parse(traw);
            if (Array.isArray(tparsed)) trash = tparsed;
        }
    } catch (e) { }
}

function updateTrashBadge() {
    try {
        const el = document.getElementById('trashCount');
        if (!el) return;
        const count = Array.isArray(trash) ? trash.length : 0;
        if (count > 0) {
            el.style.display = 'inline-block';
            el.textContent = count;
        } else {
            el.style.display = 'none';
        }
    } catch (e) { }
}

function trashStorageKey() { return 'secure_files_trash_v1'; }

// Ask for a passcode for a file using the existing UI, return a Promise that resolves with the passphrase
function askPasscodeForFile(mode, file) {
    return new Promise((resolve, reject) => {
        try {
            showPasscodePanel(mode, file, (f, pass) => {
                resolve(pass);
            });
        } catch (e) { reject(e); }
    });
}

function updateDashboardStats() {
    try {
        const total = Array.isArray(files) ? files.length : 0;
        const encryptedCount = total ? files.filter(f => f.encrypted).length : 0;
        const encryptedPct = total ? Math.round((encryptedCount / total) * 100) : 0;
        const sharedCount = total ? files.filter(f => f.permissions && f.permissions.share).length : 0;
        const threats = total ? files.filter(f => f.malware).length : 0;

        const totalEl = document.getElementById('totalFilesCount');
        const encEl = document.getElementById('filesEncryptedPct');
        const sharedEl = document.getElementById('sharedFilesCount');
        const threatEl = document.getElementById('securityThreatsCount');
        const alertEl = document.getElementById('securityAlert');
        const alertCountEl = document.getElementById('securityAlertCount');

        if (totalEl) totalEl.textContent = total;
        if (encEl) encEl.textContent = `${encryptedPct}%`;
        if (sharedEl) sharedEl.textContent = sharedCount;
        if (threatEl) threatEl.textContent = threats;

        if (alertCountEl) alertCountEl.textContent = threats;
        if (alertEl) {
            if (threats > 0) alertEl.style.display = 'flex';
            else alertEl.style.display = 'none';
        }
    } catch (e) { }
}

// DOM Elements
const authModal = document.getElementById('authModal');
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const twoFactorSection = document.getElementById('twoFactorSection');
const verify2FABtn = document.getElementById('verify2FA');
const enable2FACheckbox = document.getElementById('enable2FA');
const qrCodeContainer = document.getElementById('qrCodeContainer');
const mobileMenuBtn = document.getElementById('mobileMenuBtn');
const sidebar = document.getElementById('sidebar');
const navLinks = document.querySelectorAll('.nav-links a');
const logoutBtn = document.getElementById('logoutBtn');
const uploadBtn = document.getElementById('uploadBtn');
const closeAlert = document.getElementById('closeAlert');
const securityAlert = document.getElementById('securityAlert');
const toast = document.getElementById('toast');
const toastMessage = document.getElementById('toastMessage');
const tabs = document.querySelectorAll('.tab');
const pageContents = document.querySelectorAll('.page-content');
const fileGrid = document.querySelector('.file-grid');
const pageTitle = document.getElementById('pageTitle');
const headerSearch = document.querySelector('.search-box input');

// Dashboard controls
const dashSortBtn = () => document.getElementById('dashSortBtn');
const dashFilterBtn = () => document.getElementById('dashFilterBtn');
const dashSortControl = () => document.getElementById('dashSortControl');
const dashFilterControl = () => document.getElementById('dashFilterControl');
const dashSortSelect = () => document.getElementById('dashSortSelect');
const dashFilterType = () => document.getElementById('dashFilterType');
const dashFilterEncrypted = () => document.getElementById('dashFilterEncrypted');

// Settings elements
const themeLightBtn = document.getElementById('themeLight');
const themeDarkBtn = document.getElementById('themeDark');
const themeSystemBtn = document.getElementById('themeSystem');
const accountNameInput = document.getElementById('accountName');
const accountEmailInput = document.getElementById('accountEmail');
const saveAccountBtn = document.getElementById('saveAccountBtn');
const resetAccountBtn = document.getElementById('resetAccountBtn');

// My files elements
const myFilesGrid = document.getElementById('myFilesGrid');
const hiddenFilesGrid = document.getElementById('hiddenFilesGrid');
const showHiddenCheckbox = document.getElementById('showHiddenCheckbox');
const filterType = document.getElementById('filterType');
const filterEncrypted = document.getElementById('filterEncrypted');
const sortFiles = document.getElementById('sortFiles');

// File details modal elements
const fileDetailsModal = document.getElementById('fileDetailsModal');
const detailName = document.getElementById('detailName');
const detailType = document.getElementById('detailType');
const detailSize = document.getElementById('detailSize');
const detailModified = document.getElementById('detailModified');
const detailEncryption = document.getElementById('detailEncryption');
const detailEncIcon = document.getElementById('detailEncIcon');
const detailAccess = document.getElementById('detailAccess');
const closeFileDetailsBtn = document.getElementById('closeFileDetails');
const openFileBtn = document.getElementById('openFileBtn');
const downloadFileBtn = document.getElementById('downloadFileBtn');
const shareFileBtn = document.getElementById('shareFileBtn');
const toggleEncryptBtn = document.getElementById('toggleEncryptBtn');
const toggleHiddenBtn = document.getElementById('toggleHiddenBtn');



// Passcode panel elements
const passcodePanel = document.getElementById('passcodePanel');
const passcodeTitle = document.getElementById('passcodeTitle');
const passcodeInput = document.getElementById('passcodeInput');
const passcodeConfirmInput = document.getElementById('passcodeConfirmInput');
const passcodeSaveBtn = document.getElementById('passcodeSaveBtn');
const passcodeCancelBtn = document.getElementById('passcodeCancelBtn');
const passcodeHelp = document.getElementById('passcodeHelp');

// State variables
let isAuthenticated = false;
let twoFactorRequired = false;
let currentPage = 'dashboard';
let hiddenUnlocked = false; // session flag when master passcode for hidden files is verified
let showHiddenInMyFiles = false; // whether to include hidden files in My Files view
let dashboardState = {
    sort: 'newest',
    filterType: 'all',
    filterEncrypted: 'all'
};

// Current logged-in user's role (Administrator | Standard)
let currentUserRole = localStorage.getItem('secure_user_role') || 'Standard';

// Initialize the application
function init() {
    // Load persisted files from storage
    try { loadFilesFromStorage(); } catch (e) { }
    // Start trash cleaner
    try { startTrashCleaner(); } catch (e) { }
    try { updateTrashBadge(); } catch (e) { }
    // Check if user is already authenticated
    const savedAuth = localStorage.getItem('secureFileAuth');
    if (savedAuth === 'true') {
        isAuthenticated = true;
        authModal.classList.remove('active');
    }

    // Render files
    renderFiles();

    // Event Listeners
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }

    if (verify2FABtn) {
        verify2FABtn.addEventListener('click', verifyTwoFactor);
    }

    if (enable2FACheckbox) {
        enable2FACheckbox.addEventListener('change', toggle2FAQRCode);
    }

    // Password toggle buttons
    const setupPasswordToggle = (toggleBtnId, inputId) => {
        const toggleBtn = document.getElementById(toggleBtnId);
        const input = document.getElementById(inputId);
        if (toggleBtn && input) {
            toggleBtn.addEventListener('click', (e) => {
                e.preventDefault();
                const isPassword = input.type === 'password';
                input.type = isPassword ? 'text' : 'password';
                toggleBtn.innerHTML = isPassword
                    ? '<i class="fas fa-eye-slash"></i>'
                    : '<i class="fas fa-eye"></i>';
            });
        }
    };

    setupPasswordToggle('loginPasswordToggle', 'loginPassword');
    setupPasswordToggle('registerPasswordToggle', 'registerPassword');
    setupPasswordToggle('confirmPasswordToggle', 'confirmPassword');

    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', toggleSidebar);
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }

    if (uploadBtn) {
        uploadBtn.addEventListener('click', handleUpload);
    }

    if (closeAlert) {
        closeAlert.addEventListener('click', () => {
            securityAlert.style.display = 'none';
        });
    }

    // Header search input -> filter current view
    if (headerSearch) {
        headerSearch.addEventListener('input', () => {
            if (currentPage === 'dashboard') renderFiles();
            if (currentPage === 'files') renderMyFiles();
        });
    }

    // Settings handlers
    if (themeLightBtn) themeLightBtn.addEventListener('click', () => applyTheme('light'));
    if (themeDarkBtn) themeDarkBtn.addEventListener('click', () => applyTheme('dark'));
    if (themeSystemBtn) themeSystemBtn.addEventListener('click', () => applyTheme('system'));
    if (saveAccountBtn) saveAccountBtn.addEventListener('click', saveAccountDetails);
    if (resetAccountBtn) resetAccountBtn.addEventListener('click', loadAccountDetails);

    // My files filters
    if (filterType) filterType.addEventListener('change', renderMyFiles);
    if (filterEncrypted) filterEncrypted.addEventListener('change', renderMyFiles);
    if (sortFiles) sortFiles.addEventListener('change', renderMyFiles);
    // Show Hidden Only checkbox: require master passcode when enabling
    if (showHiddenCheckbox) {
        // initialize checkbox state
        showHiddenCheckbox.checked = !!showHiddenInMyFiles;
        showHiddenCheckbox.addEventListener('change', () => {
            // If unchecked -> show only non-hidden files
            if (!showHiddenCheckbox.checked) {
                showHiddenInMyFiles = false;
                renderMyFiles();
                return;
            }

            // If checking the box, require master passcode before showing hidden files
            const key = localStorage.getItem(masterPassKey());
            if (!key) {
                showMasterPasscodePanel('create', () => {
                    hiddenUnlocked = true;
                    showHiddenInMyFiles = true;
                    renderMyFiles();
                });
            } else {
                showMasterPasscodePanel('verify', () => {
                    hiddenUnlocked = true;
                    showHiddenInMyFiles = true;
                    renderMyFiles();
                });
            }
        });
    }

    // Password strength meter for registration
    const regPw = document.getElementById('registerPassword');
    const pwBar = document.getElementById('pwStrengthBar');
    const pwText = document.getElementById('pwStrengthText');
    if (regPw) {
        regPw.addEventListener('input', () => {
            const s = checkPasswordStrength(regPw.value);
            if (pwBar) { pwBar.style.width = `${s.percent}%`; pwBar.style.background = s.color; }
            if (pwText) pwText.textContent = s.text;
        });
    }

    // Initialize register role select
    const regRole = document.getElementById('registerRole');
    if (regRole) regRole.value = localStorage.getItem('secure_user_role') || 'Standard';

    // Email verification modal handlers
    const verifyBtn = document.getElementById('verifyCodeBtn');
    const cancelVerifyBtn = document.getElementById('cancelVerifyBtn');
    if (verifyBtn) verifyBtn.addEventListener('click', handleVerifyCode);
    if (cancelVerifyBtn) cancelVerifyBtn.addEventListener('click', () => {
        const mv = document.getElementById('emailVerificationModal'); if (mv) mv.classList.remove('active');
    });

    // Load persisted theme and account
    loadTheme();
    loadAccountDetails();
    renderMyFiles();

    // Tab switching
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabId = tab.getAttribute('data-tab');
            switchTab(tabId);
        });
    });

    // Navigation
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.getAttribute('data-page');

            // Update active state
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');

            // Show the selected page
            showPage(page);

            // Close sidebar on mobile
            if (window.innerWidth < 992) {
                sidebar.classList.remove('active');
            }
        });
    });

    // Initialize security toggles
    const malwareToggle = document.getElementById('malwareToggle');
    if (malwareToggle) {
        malwareToggle.addEventListener('change', (e) => {
            showToast(`Malware detection ${e.target.checked ? 'enabled' : 'disabled'}`, e.target.checked ? 'success' : 'error');
        });
    }

    const bufferToggle = document.getElementById('bufferToggle');
    if (bufferToggle) {
        bufferToggle.addEventListener('change', (e) => {
            showToast(`Buffer overflow protection ${e.target.checked ? 'enabled' : 'disabled'}`, e.target.checked ? 'success' : 'error');
        });
    }

    // Start inactivity timer (lock session after inactivity)
    setupInactivityDetector();


}

// Render files to the file grid
function renderFiles() {
    if (!fileGrid) return;

    const query = headerSearch ? headerSearch.value.trim().toLowerCase() : '';

    fileGrid.innerHTML = '';

    files.forEach(file => {
        if (query) {
            if (!file.name.toLowerCase().includes(query)) return;
        }
        // show hidden files in dashboard but mark them visually as hidden
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item' + (file.hidden ? ' hidden-file' : '');

        // Determine icon class based on file type
        let iconClass = '';
        switch (file.type) {
            case 'pdf': iconClass = 'pdf'; break;
            case 'docx': iconClass = 'docx'; break;
            case 'xlsx': iconClass = 'xlsx'; break;
            case 'pptx': iconClass = 'docx'; break;
            case 'img': iconClass = 'img'; break;
            case 'zip': iconClass = 'blue'; break;
            default: iconClass = 'blue';
        }

        // Determine icon based on file type
        let icon = 'fa-file';
        switch (file.type) {
            case 'pdf': icon = 'fa-file-pdf'; break;
            case 'docx':
            case 'pptx': icon = 'fa-file-word'; break;
            case 'xlsx': icon = 'fa-file-excel'; break;
            case 'img': icon = 'fa-file-image'; break;
            case 'zip': icon = 'fa-file-archive'; break;
            case 'txt': icon = 'fa-file-alt'; break;
        }

        fileItem.innerHTML = `
            <div class="file-icon ${iconClass}">
                <i class="fas ${icon}"></i>
            </div>
            <div class="file-name">${file.name}</div>
            <div class="file-meta">
                ${file.size} â€¢ ${file.date}
            </div>
            <div class="file-meta">
                ${file.encrypted ? '<i class="fas fa-lock" style="color: #4cc9f0; margin-right: 5px;"></i> Encrypted' : '<i class="fas fa-unlock" style="color: #f8961e; margin-right: 5px;"></i> Not Encrypted'}
            </div>
            <div class="file-options">
                <button class="view-btn" data-id="${file.id}" title="View"><i class="fas fa-eye"></i></button>
                <button class="share-btn" data-id="${file.id}" title="Share"><i class="fas fa-share-alt"></i></button>
                <button class="hidden-btn" data-id="${file.id}" title="Hide"><i class="fas fa-eye-slash"></i></button>
                <button class="encrypt-btn" data-id="${file.id}" title="${file.encrypted ? 'Decrypt' : 'Encrypt'}">
                    <i class="fas ${file.encrypted ? 'fa-unlock' : 'fa-lock'}"></i>
                </button>
                <button class="delete-btn" data-id="${file.id}" title="Delete"><i class="fas fa-trash"></i></button>
            </div>
        `;
        // If file is hidden, add a subtle badge/overlay to indicate restricted access
        if (file.hidden) {
            const badge = document.createElement('div');
            badge.className = 'hidden-badge';
            badge.innerHTML = '<i class="fas fa-lock"></i> Hidden';
            fileItem.appendChild(badge);
        }

        fileGrid.appendChild(fileItem);
    });

    // Add event listeners to file action buttons
    attachFileEventListeners();
    try { updateDashboardStats(); } catch (e) { }
}

// Render files specifically for the My Files page with filters
function renderMyFiles() {
    if (!myFilesGrid) return;

    let list = [...files];
    // If the "Show Hidden Only" checkbox is checked, display only hidden files.
    // Otherwise display only non-hidden files.
    if (showHiddenInMyFiles) {
        list = list.filter(f => f.hidden);
    } else {
        list = list.filter(f => !f.hidden);
    }

    // Apply search
    const q = headerSearch ? headerSearch.value.trim().toLowerCase() : '';
    if (q) list = list.filter(f => f.name.toLowerCase().includes(q));

    // Type filter
    if (filterType && filterType.value !== 'all') {
        list = list.filter(f => f.type === filterType.value);
    }

    // Encryption filter
    if (filterEncrypted) {
        if (filterEncrypted.value === 'enc') list = list.filter(f => f.encrypted);
        if (filterEncrypted.value === 'not') list = list.filter(f => !f.encrypted);
    }

    // Sort
    if (sortFiles) {
        if (sortFiles.value === 'newest') list.sort((a, b) => new Date(b.date) - new Date(a.date));
        if (sortFiles.value === 'oldest') list.sort((a, b) => new Date(a.date) - new Date(b.date));
        if (sortFiles.value === 'name') list.sort((a, b) => a.name.localeCompare(b.name));
    }

    myFilesGrid.innerHTML = '';

    list.forEach(file => {
        const item = document.createElement('div');
        item.className = 'file-item';

        let iconClass = '';
        switch (file.type) {
            case 'pdf': iconClass = 'pdf'; break;
            case 'docx': iconClass = 'docx'; break;
            case 'xlsx': iconClass = 'xlsx'; break;
            case 'img': iconClass = 'img'; break;
            case 'zip': iconClass = 'blue'; break;
            default: iconClass = 'blue';
        }

        let icon = 'fa-file';
        switch (file.type) {
            case 'pdf': icon = 'fa-file-pdf'; break;
            case 'docx': icon = 'fa-file-word'; break;
            case 'xlsx': icon = 'fa-file-excel'; break;
            case 'img': icon = 'fa-file-image'; break;
            case 'zip': icon = 'fa-file-archive'; break;
            case 'txt': icon = 'fa-file-alt'; break;
        }

        item.innerHTML = `
            <div class="file-icon ${iconClass}">
                <i class="fas ${icon}"></i>
            </div>
            <div class="file-name">${file.name}</div>
            <div class="file-meta">${file.size} â€¢ ${file.date}</div>
            <div class="file-meta">${file.encrypted ? '<i class="fas fa-lock" style="color: #4cc9f0; margin-right: 5px;"></i> Encrypted' : '<i class="fas fa-unlock" style="color: #f8961e; margin-right: 5px;"></i> Not Encrypted'}</div>
            <div class="file-options">
                <button class="view-btn" data-id="${file.id}" title="View"><i class="fas fa-eye"></i></button>
                <button class="share-btn" data-id="${file.id}" title="Share"><i class="fas fa-share-alt"></i></button>
                <button class="hidden-btn" data-id="${file.id}" title="Hide"><i class="fas fa-eye-slash"></i></button>
                <button class="encrypt-btn" data-id="${file.id}" title="Toggle Encrypt"><i class="fas fa-lock"></i></button>
                <button class="delete-btn" data-id="${file.id}" title="Delete"><i class="fas fa-trash"></i></button>
            </div>
        `;

        myFilesGrid.appendChild(item);
    });

    // Re-attach listeners for the newly created controls
    attachFileEventListeners();
    try { updateDashboardStats(); } catch (e) { }
}

// Attach event listeners to file action buttons
function attachFileEventListeners() {
    document.querySelectorAll('.view-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const fileId = btn.getAttribute('data-id');
            const file = files.find(f => f.id == fileId);
            if (file) {
                if (!checkPermission(file, 'view')) {
                    showPermissionDenied('view');
                    return;
                }
                showFileDetails(file);
            }
        });
    });

    document.querySelectorAll('.share-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const fileId = btn.getAttribute('data-id');
            const file = files.find(f => f.id == fileId);
            if (!file) return;
            // create a dummy share link (in a real app this would be generated/server-side)
            const shareUrl = `${location.origin}${location.pathname}#share-${file.id}`;
            // try clipboard API
            try {
                await navigator.clipboard.writeText(shareUrl);
                showToast(`Share link copied for "${file.name}"`, 'success');
            } catch (e) {
                // fallback: prompt user
                window.prompt('Copy this link to share:', shareUrl);
                showToast('Share link â€” copy it manually', 'info');
            }
        });
    });

    // Open the details modal when clicking the encrypt/toggle button so user can confirm/passcode
    document.querySelectorAll('.encrypt-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const fileId = btn.getAttribute('data-id');
            const file = files.find(f => f.id == fileId);
            if (file) {
                showFileDetails(file);
            }
        });
    });

    document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const fileId = btn.getAttribute('data-id');
            const fileIndex = files.findIndex(f => f.id == fileId);
            if (fileIndex !== -1) {
                const file = files[fileIndex];
                if (!checkPermission(file, 'delete')) {
                    showPermissionDenied('delete');
                    return;
                }
                const fileName = file.name;
                if (confirm(`Move "${fileName}" to Recycle Bin?`)) {
                    // move to trash with deletion timestamp (30 minutes TTL)
                    try {
                        const f = files[fileIndex];
                        const now = Date.now();
                        const expiresAt = now + (30 * 60 * 1000); // 30 minutes
                        const trashed = Object.assign({}, f, { deletedAt: now, expiresAt });
                        // If there's a blob URL, keep a reference so we can revoke when permanently deleting
                        if (f.url) trashed.url = f.url;
                        trash.unshift(trashed);
                        // remove from active files
                        files.splice(fileIndex, 1);
                        saveFilesToStorage();
                        renderFiles();
                        renderMyFiles();
                        try { renderTrash(); } catch (e) { }
                        showToast(`"${fileName}" moved to Recycle Bin`, 'success');
                    } catch (err) {
                        showToast('Failed to move to Recycle Bin', 'error');
                    }
                }
            }
        });
    });

    // Hide / Unhide buttons on cards
    document.querySelectorAll('.hidden-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const fileId = btn.getAttribute('data-id');
            const file = files.find(f => f.id == fileId);
            if (!file) return;

            if (!file.hidden) {
                // hide flow: admins can hide without master pass, others need master pass
                if (currentUserRole === 'Administrator') {
                    file.hidden = true;
                    renderFiles();
                    renderMyFiles();
                    renderHiddenFiles();
                    showToast(`"${file.name}" moved to Hidden`, 'success');
                } else {
                    const key = localStorage.getItem(masterPassKey());
                    if (!key) {
                        showMasterPasscodePanel('create', () => {
                            hiddenUnlocked = true;
                            file.hidden = true;
                            renderFiles();
                            renderMyFiles();
                            renderHiddenFiles();
                            showToast(`"${file.name}" moved to Hidden`, 'success');
                        });
                    } else {
                        file.hidden = true;
                        renderFiles();
                        renderMyFiles();
                        renderHiddenFiles();
                        showToast(`"${file.name}" moved to Hidden`, 'success');
                    }
                }
            } else {
                // unhide: admins can unhide without master verification, others require master verification
                if (currentUserRole === 'Administrator') {
                    file.hidden = false;
                    renderFiles();
                    renderMyFiles();
                    renderHiddenFiles();
                    showToast(`"${file.name}" restored from Hidden`, 'success');
                } else {
                    showMasterPasscodePanel('verify', () => {
                        hiddenUnlocked = true;
                        file.hidden = false;
                        renderFiles();
                        renderMyFiles();
                        renderHiddenFiles();
                        showToast(`"${file.name}" restored from Hidden`, 'success');
                    });
                }
            }
        });
    });

    // Clicking the file item (outside the small action buttons) should open details
    document.querySelectorAll('.file-item').forEach(elem => {
        elem.addEventListener('click', (e) => {
            // ignore clicks on action buttons
            if (e.target.closest('.file-options')) return;
            const id = elem.querySelector('.view-btn')?.getAttribute('data-id');
            if (id) {
                const file = files.find(f => f.id == id);
                if (file) showFileDetails(file);
            }
        });
    });
}

let _currentFile = null;

// showFileDetails: wrapper that enforces master passcode for hidden files, then calls the unlocked renderer
function showFileDetails(file) {
    if (file.hidden && !hiddenUnlocked && currentUserRole !== 'Administrator') {
        const key = localStorage.getItem(masterPassKey());
        if (!key) {
            // create master then show details
            showMasterPasscodePanel('create', () => {
                hiddenUnlocked = true;
                showFileDetailsUnlocked(file);
            });
        } else {
            showMasterPasscodePanel('verify', () => {
                hiddenUnlocked = true;
                showFileDetailsUnlocked(file);
            });
        }
        return;
    }
    showFileDetailsUnlocked(file);
}

function showFileDetailsUnlocked(file) {
    _currentFile = file;
    if (!fileDetailsModal) return;
    detailName.textContent = file.name;
    detailType.textContent = file.type.toUpperCase();
    detailSize.textContent = file.size || 'â€”';
    // show a human-friendly modified date
    detailModified.textContent = file.date || new Date().toLocaleString();
    detailEncryption.textContent = file.encrypted ? 'Encrypted (AES-256)' : 'Not Encrypted';
    detailEncIcon.style.color = file.encrypted ? '#4cc9f0' : '#f8961e';
    detailAccess.textContent = file.role || 'Owner';
    // update toggle button text
    toggleEncryptBtn.textContent = file.encrypted ? 'Disable Encryption' : 'Enable Encryption';
    if (toggleHiddenBtn) toggleHiddenBtn.textContent = file.hidden ? 'Unhide' : 'Hide';

    // show modal
    fileDetailsModal.classList.add('active');

    // Render RBAC controls
    const rbacEl = document.getElementById('rbacControls');
    if (rbacEl) {
        rbacEl.innerHTML = '';
        const roleLabel = document.createElement('div');
        roleLabel.style.marginBottom = '12px';
        roleLabel.style.display = 'flex';
        roleLabel.style.alignItems = 'center';
        roleLabel.style.flexWrap = 'wrap';
        roleLabel.style.gap = '15px';

        roleLabel.innerHTML = `<strong style="color:#fff; margin-right:8px;">Role:</strong>`;

        const roleSelect = document.createElement('select');
        roleSelect.style.padding = '6px 12px';
        roleSelect.style.borderRadius = '6px';
        roleSelect.style.border = 'none';
        roleSelect.style.background = '#2a2d3a';
        roleSelect.style.color = '#fff';
        ['Owner', 'Admin', 'User', 'Guest'].forEach(r => {
            const opt = document.createElement('option');
            opt.value = r;
            opt.text = r;
            roleSelect.appendChild(opt);
        });
        roleSelect.value = file.role || 'Owner';
        roleSelect.onchange = () => {
            file.role = roleSelect.value;
            detailAccess.textContent = file.role;
            saveFilesToStorage();
        };

        roleLabel.appendChild(roleSelect);

        // Add permission icons (read-only display - only show enabled permissions)
        const permContainer = document.createElement('div');
        permContainer.style.display = 'inline-flex';
        permContainer.style.gap = '12px';
        permContainer.style.marginLeft = '15px';
        permContainer.style.flexWrap = 'wrap';

        const perms = file.permissions || { view: true, download: true, edit: true, canDelete: true };
        const permissionsList = [
            { key: 'view', label: 'View', icon: 'fa-eye', color: '#6366f1' },
            { key: 'download', label: 'Download', icon: 'fa-download', color: '#10b981' },
            { key: 'edit', label: 'Edit', icon: 'fa-edit', color: '#f59e0b' },
            { key: 'canDelete', label: 'Delete', icon: 'fa-trash', color: '#ef4444' }
        ];

        permissionsList.forEach(perm => {
            // Only show icons for ENABLED permissions
            if (perms[perm.key]) {
                const permItem = document.createElement('div');
                permItem.style.display = 'inline-flex';
                permItem.style.alignItems = 'center';
                permItem.style.gap = '5px';
                permItem.style.padding = '4px 8px';
                permItem.style.background = 'rgba(99, 102, 241, 0.1)';
                permItem.style.borderRadius = '4px';
                permItem.title = `${perm.label} permission granted`;

                const icon = document.createElement('i');
                icon.className = `fas ${perm.icon}`;
                icon.style.color = perm.color;
                icon.style.fontSize = '13px';
                permItem.appendChild(icon);

                const span = document.createElement('span');
                span.style.color = '#9fb3d7';
                span.style.fontSize = '12px';
                span.textContent = perm.label;
                permItem.appendChild(span);

                permContainer.appendChild(permItem);
            }
        });

        roleLabel.appendChild(permContainer);
        rbacEl.appendChild(roleLabel);
    }

    // attach button handlers (safe to reattach)
    if (closeFileDetailsBtn) closeFileDetailsBtn.onclick = hideFileDetails;
    if (openFileBtn) openFileBtn.onclick = () => {
        if (_currentFile) {
            if (!checkPermission(_currentFile, 'view')) {
                showPermissionDenied('open/view');
                return;
            }
            tryOpenFile(_currentFile);
        }
    };
    if (downloadFileBtn) downloadFileBtn.onclick = () => {
        if (_currentFile) {
            if (!checkPermission(_currentFile, 'download')) {
                showPermissionDenied('download');
                return;
            }
            ensureDownload(_currentFile);
        }
    };
    if (shareFileBtn) shareFileBtn.onclick = async () => {
        const shareUrl = `${location.origin}${location.pathname}#share-${file.id}`;
        try { await navigator.clipboard.writeText(shareUrl); showToast(`Share link copied for "${file.name}"`, 'success'); }
        catch (e) { window.prompt('Copy this link to share:', shareUrl); showToast('Share link â€” copy it manually', 'info'); }
    };
    if (toggleEncryptBtn) toggleEncryptBtn.onclick = () => {
        if (!_currentFile) return;
        if (!checkPermission(_currentFile, 'edit')) {
            showPermissionDenied('edit encryption settings');
            return;
        }
        const currentFile = _currentFile;
        // If file is currently encrypted and user wants to disable it, require passcode verification
        if (currentFile.encrypted) {
            showPasscodePanel('verify', currentFile, () => {
                // verified -> decrypt
                currentFile.encrypted = false;
                detailEncryption.textContent = 'Not Encrypted';
                detailEncIcon.style.color = '#f8961e';
                toggleEncryptBtn.textContent = 'Enable Encryption';
                try { localStorage.removeItem(passcodeStorageKey(currentFile.id)); } catch (e) { }
                renderFiles();
                renderMyFiles();
                showToast('File decrypted', 'success');
            });
        } else {
            // enabling encryption: require creating a passcode
            showPasscodePanel('create', currentFile, () => {
                currentFile.encrypted = true;
                detailEncryption.textContent = 'Encrypted (AES-256)';
                detailEncIcon.style.color = '#4cc9f0';
                toggleEncryptBtn.textContent = 'Disable Encryption';
                renderFiles();
                renderMyFiles();
                showToast('File encrypted and passcode set', 'success');
            });
        }
    };

    if (toggleHiddenBtn) toggleHiddenBtn.onclick = () => {
        if (!_currentFile) return;
        const currentFile = _currentFile;
        // Hide/unhide: Administrators can do this without master pass; others require master passflow
        if (!currentFile.hidden) {
            if (currentUserRole === 'Administrator') {
                currentFile.hidden = true;
                renderFiles();
                renderMyFiles();
                renderHiddenFiles();
                hideFileDetails();
                showToast('File hidden', 'success');
            } else {
                const key = localStorage.getItem(masterPassKey());
                if (!key) {
                    showMasterPasscodePanel('create', () => {
                        hiddenUnlocked = true;
                        file.hidden = true;
                        renderFiles();
                        renderMyFiles();
                        renderHiddenFiles();
                        hideFileDetails();
                        showToast('File hidden', 'success');
                    });
                } else {
                    file.hidden = true;
                    renderFiles();
                    renderMyFiles();
                    renderHiddenFiles();
                    hideFileDetails();
                    showToast('File hidden', 'success');
                }
            }
        } else {
            if (currentUserRole === 'Administrator') {
                currentFile.hidden = false;
                renderFiles();
                renderMyFiles();
                renderHiddenFiles();
                hideFileDetails();
                showToast('File unhidden', 'success');
            } else {
                // unhide - require verification
                showMasterPasscodePanel('verify', () => {
                    hiddenUnlocked = true;
                    currentFile.hidden = false;
                    renderFiles();
                    renderMyFiles();
                    renderHiddenFiles();
                    hideFileDetails();
                    showToast('File unhidden', 'success');
                });
            }
        }
    };

    // close when click outside card
    fileDetailsModal.onclick = (e) => {
        if (e.target === fileDetailsModal) hideFileDetails();
    };
}

function hideFileDetails() {
    if (!fileDetailsModal) return;
    fileDetailsModal.classList.remove('active');
    _currentFile = null;
}

function downloadDummyFile(file) {
    // Create a simple blob to simulate a download
    const content = `This is a simulated download for ${file.name}`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = file.name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast(`Downloading "${file.name}"`, 'success');
}

// Use real blob URL if available, otherwise fall back to dummy download
function ensureDownload(file) {
    // We need to enforce master passcode for hidden files, then per-file passcode for encrypted files.
    const proceedWithPerFile = () => {
        // If file is encrypted, require per-file passcode (create if none)
        if (file.encrypted) {
            const key = passcodeStorageKey(file.id);
            const stored = localStorage.getItem(key);
            if (!stored) {
                showPasscodePanel('create', file, (f, pass) => { decryptAndDownload(f, pass); });
                return;
            }
            showPasscodePanel('verify', file, (f, pass) => { decryptAndDownload(f, pass); });
            return;
        }
        _doDownload(file);
    };

    if (file.hidden) {
        // Administrators can bypass master pass for hidden files
        if (currentUserRole === 'Administrator') { proceedWithPerFile(); return; }
        if (hiddenUnlocked) { proceedWithPerFile(); return; }
        const key = localStorage.getItem(masterPassKey());
        if (!key) {
            showMasterPasscodePanel('create', () => { hiddenUnlocked = true; proceedWithPerFile(); });
            return;
        }
        showMasterPasscodePanel('verify', () => { hiddenUnlocked = true; proceedWithPerFile(); });
        return;
    }

    proceedWithPerFile();
}

function _doDownload(file) {
    try {
        if (file.url) {
            const a = document.createElement('a');
            a.href = file.url;
            a.download = file.name;
            document.body.appendChild(a);
            a.click();
            a.remove();
            showToast(`Downloading "${file.name}"`, 'success');
            return;
        }
    } catch (e) {
        // ignore and fallback
    }
    downloadDummyFile(file);
}

// Decrypt with per-file passphrase and download
async function decryptAndDownload(file, passphrase) {
    try {
        const saltBuf = base64ToArrayBuffer(file.salt);
        const key = await deriveKeyFromPassword(passphrase, new Uint8Array(saltBuf));
        const plain = await decryptBuffer(key, file.iv, file.encryptedData);
        const integrity = await sha256Buffer(plain);
        if (file.integrityHash && file.integrityHash !== integrity) {
            showToast('File integrity check failed â€” possible tampering', 'error');
            return;
        }
        const blob = new Blob([plain]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = file.name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        showToast(`Downloading "${file.name}"`, 'success');
    } catch (err) {
        showToast('Decryption failed: incorrect passphrase or corrupted file', 'error');
    }
}

// --------------------- Passcode / Open logic ---------------------
// Use browser crypto to hash passcodes before storing in localStorage
async function sha256Hex(message) {
    const msgUint8 = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

// Password strength checker
function checkPasswordStrength(pw) {
    const rules = {
        length: pw.length >= 8,
        number: /[0-9]/.test(pw),
        upper: /[A-Z]/.test(pw),
        symbol: /[^A-Za-z0-9]/.test(pw)
    };
    const passed = Object.values(rules).filter(Boolean).length;
    let text = 'Weak';
    let color = '#f8961e';
    let percent = (passed / 4) * 100;
    if (passed <= 1) { text = 'Weak'; color = '#f72585'; }
    else if (passed === 2 || passed === 3) { text = 'Medium'; color = '#f8961e'; }
    else if (passed === 4) { text = 'Strong'; color = '#4cc9f0'; }
    return { rules, passed, text, color, percent };
}

// Email verification demo helpers
function generateVerificationCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function showEmailVerificationModal(code) {
    const mv = document.getElementById('emailVerificationModal');
    const help = document.getElementById('verifHelp');
    if (!mv) return;
    // For demo show the code so tester can enter it (no real email)
    if (help) help.textContent = `Demo verification code: ${code}`;
    mv.classList.add('active');
}

async function handleVerifyCode() {
    const input = document.getElementById('verifCodeInput');
    const help = document.getElementById('verifHelp');
    if (!input) return;
    const v = input.value.trim();
    const stored = localStorage.getItem('secure_verif_code');
    if (!stored) { if (help) help.textContent = 'No verification code found.'; return; }
    if (v === stored) {
        // Activate pending user
        const pendingRaw = localStorage.getItem('secure_pending_user');
        if (pendingRaw) {
            const u = JSON.parse(pendingRaw);
            u.activated = true;
            localStorage.setItem('secure_user', JSON.stringify(u));
            localStorage.setItem('secure_user_role', u.role || 'Standard');
            // cleanup
            localStorage.removeItem('secure_pending_user');
            localStorage.removeItem('secure_verif_code');
            currentUserRole = u.role || 'Standard';
            // hide modal
            const mv = document.getElementById('emailVerificationModal'); if (mv) mv.classList.remove('active');
            showToast('Email verified â€” account activated. Please log in.', 'success');
            // switch to login tab
            switchTab('login');
        }
    } else {
        if (help) help.textContent = 'Incorrect code. Try again.';
        showToast('Incorrect verification code', 'error');
    }
}

function passcodeStorageKey(fileId) {
    return `file_pass_${fileId}`;
}

// SHA-256 for ArrayBuffer -> hex
async function sha256Buffer(buffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

function getRandomSalt() {
    const s = new Uint8Array(16);
    crypto.getRandomValues(s);
    return s;
}

async function deriveKeyFromPassword(password, salt) {
    const enc = new TextEncoder().encode(password);
    const keyMaterial = await crypto.subtle.importKey('raw', enc, { name: 'PBKDF2' }, false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    return key;
}

async function encryptBuffer(key, buffer) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buffer);
    return { iv: arrayBufferToBase64(iv.buffer), data: arrayBufferToBase64(ct) };
}

async function decryptBuffer(key, ivBase64, dataBase64) {
    const iv = new Uint8Array(base64ToArrayBuffer(ivBase64));
    const ct = base64ToArrayBuffer(dataBase64);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return plain; // ArrayBuffer
}

// Ensure the passcode panel is visible even when the file details modal
// is not open (e.g. when enabling 'Show Hidden' from My Files).
function closePasscodeUI() {
    if (passcodePanel) passcodePanel.style.display = 'none';
    // Only hide the file details modal if we're not currently viewing a file
    if (!_currentFile && fileDetailsModal) fileDetailsModal.classList.remove('active');
}

// Wrapper: require master passcode if file is hidden, then continue to per-file open logic
function tryOpenFile(file) {
    if (file.hidden) {
        // Administrators can bypass master pass
        if (currentUserRole === 'Administrator') { tryOpenFileUnlocked(file); return; }
        // If session already unlocked, continue. Otherwise verify master passcode.
        if (hiddenUnlocked) {
            tryOpenFileUnlocked(file);
        } else {
            const key = localStorage.getItem(masterPassKey());
            if (!key) {
                showMasterPasscodePanel('create', () => {
                    // allow immediate open after creating master
                    tryOpenFileUnlocked(file);
                });
            } else {
                showMasterPasscodePanel('verify', () => {
                    hiddenUnlocked = true;
                    tryOpenFileUnlocked(file);
                });
            }
        }
        return;
    }
    tryOpenFileUnlocked(file);
}

// Actual open logic (previous tryOpenFile)
function tryOpenFileUnlocked(file) {
    if (!file.encrypted) {
        openFile(file);
        return;
    }

    const key = passcodeStorageKey(file.id);
    const storedHash = localStorage.getItem(key);

    if (!storedHash) {
        // first time: ask user to create a passcode
        showPasscodePanel('create', file, () => {
            // after creating passcode, open the file
            openFile(file);
        });
        return;
    }

    // ask user to enter passcode to verify, then decrypt and open
    showPasscodePanel('verify', file, async (f, pass) => {
        console.log('Passcode verified, decrypting file:', file.name);
        // Decrypt the file with the verified passphrase
        if (file.encryptedData) {
            try {
                const saltBuf = base64ToArrayBuffer(file.salt);
                const derivedKey = await deriveKeyFromPassword(pass, new Uint8Array(saltBuf));
                const plain = await decryptBuffer(derivedKey, file.iv, file.encryptedData);
                const integrity = await sha256Buffer(plain);
                if (file.integrityHash && file.integrityHash !== integrity) {
                    showToast('File integrity check failed — possible tampering', 'error');
                    return;
                }

                // Create blob URL
                const ext = (file.originalExt || '').toLowerCase();
                const mimeMap = {
                    pdf: 'application/pdf',
                    jpg: 'image/jpeg',
                    jpeg: 'image/jpeg',
                    png: 'image/png',
                    gif: 'image/gif',
                    webp: 'image/webp',
                    svg: 'image/svg+xml',
                    txt: 'text/plain',
                    json: 'application/json',
                    html: 'text/html',
                    csv: 'text/csv',
                    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                };
                const mime = (file.originalMime && file.originalMime !== '') ? file.originalMime : (mimeMap[ext] || 'application/octet-stream');
                const blob = new Blob([plain], { type: mime });
                const url = URL.createObjectURL(blob);
                file.blobUrl = url;

                showToast(`Opening "${file.name}"`, 'success');
                openInViewer(file, url);
            } catch (err) {
                showToast('Decryption failed: incorrect passphrase or corrupted file', 'error');
                console.error('Decryption error:', err);
            }
        } else {
            // No encrypted data, just open normally
            openFile(file);
        }
    });
}

function openInViewer(file, url) {
    const params = new URLSearchParams();
    if (url) params.set('url', url);
    params.set('name', file.name || 'Unknown');
    params.set('type', file.type || 'unknown');
    if (file.originalExt) params.set('ext', file.originalExt);
    if (file.originalMime) params.set('mime', file.originalMime);

    window.open('viewer.html?' + params.toString(), '_blank');
}

function openFile(file) {
    // Helper to create blob URL from plain buffer using original mime/extension
    const createBlobUrl = (plain) => {
        const ext = (file.originalExt || '').toLowerCase();
        const mimeMap = {
            pdf: 'application/pdf',
            jpg: 'image/jpeg',
            jpeg: 'image/jpeg',
            png: 'image/png',
            gif: 'image/gif',
            webp: 'image/webp',
            svg: 'image/svg+xml',
            txt: 'text/plain',
            json: 'application/json',
            html: 'text/html',
            csv: 'text/csv',
            docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        };
        const mime = (file.originalMime && file.originalMime !== '') ? file.originalMime : (mimeMap[ext] || 'application/octet-stream');
        const blob = new Blob([plain], { type: mime });
        const url = URL.createObjectURL(blob);
        file.blobUrl = url;
        return url;
    };

    // If encrypted data exists, decrypt with per-file passphrase then open
    if (file.encrypted && file.encryptedData) {
        showPasscodePanel('verify', file, async (f, pass) => {
            try {
                const saltBuf = base64ToArrayBuffer(file.salt);
                const key = await deriveKeyFromPassword(pass, new Uint8Array(saltBuf));
                const plain = await decryptBuffer(key, file.iv, file.encryptedData);
                const integrity = await sha256Buffer(plain);
                if (file.integrityHash && file.integrityHash !== integrity) {
                    showToast('File integrity check failed â€” possible tampering', 'error');
                    return;
                }
                const url = createBlobUrl(plain);
                showToast(`Opening \"${file.name}\"`, 'success');
                openInViewer(file, url);
            } catch (err) {
                showToast('Decryption failed: incorrect passphrase or corrupted file', 'error');
            }
        });
        return;
    }

    // If a blob/url already exists, use the viewer
    if (file.url || file.blobUrl) {
        const url = file.url || file.blobUrl;
        showToast(`Opening \"${file.name}\"`, 'success');
        openInViewer(file, url);
        return;
    }

    // Fallback: file has no data (sample/demo file)
    showToast(`Cannot open \"${file.name}\" - this is a sample file without actual data. Please upload a real file.`, 'error');
}

function showPasscodePanel(mode, file, onSuccess) {
    if (!passcodePanel) return;
    // Ensure the parent modal is visible so passcodePanel can be interacted with
    if (fileDetailsModal) fileDetailsModal.classList.add('active');
    passcodePanel.style.display = 'block';
    passcodeHelp.textContent = '';
    passcodeInput.value = '';
    passcodeConfirmInput.value = '';

    if (mode === 'create') {
        passcodeTitle.textContent = 'Create a passcode for this file';
        passcodeConfirmInput.style.display = 'block';
        passcodeSaveBtn.textContent = 'Save';
    } else {
        passcodeTitle.textContent = 'Enter passcode to open file';
        passcodeConfirmInput.style.display = 'none';
        passcodeSaveBtn.textContent = 'Verify';
    }

    // handlers
    passcodeCancelBtn.onclick = () => { closePasscodeUI(); };
    passcodeSaveBtn.onclick = async () => {
        const v = passcodeInput.value.trim();
        if (!v) {
            passcodeHelp.textContent = 'Passcode cannot be empty.';
            return;
        }

        const key = passcodeStorageKey(file.id);

        if (mode === 'create') {
            const confirm = passcodeConfirmInput.value.trim();
            if (v.length < 4) {
                passcodeHelp.textContent = 'Choose a stronger passcode (min 4 chars).';
                return;
            }
            if (v !== confirm) {
                passcodeHelp.textContent = 'Passcodes do not match.';
                return;
            }
            const h = await sha256Hex(v);
            localStorage.setItem(key, h);
            closePasscodeUI();
            showToast('Passcode created.', 'success');
            if (typeof onSuccess === 'function') onSuccess(file, v);
            else openFile(file);
        } else {
            const stored = localStorage.getItem(key);
            if (!stored) {
                passcodeHelp.textContent = 'No passcode exists for this file.';
                return;
            }
            const h = await sha256Hex(v);
            if (h === stored) {
                closePasscodeUI();
                showToast('Passcode verified.', 'success');
                if (typeof onSuccess === 'function') onSuccess(file, v);
                else openFile(file);
            } else {
                passcodeHelp.textContent = 'Incorrect passcode. Try again.';
                showToast('Incorrect passcode', 'error');
            }
        }
    };
}

// -------------------- Master passcode for Hidden Files --------------------
function masterPassKey() { return 'hidden_master_pass'; }

function showMasterPasscodePanel(mode, onSuccess) {
    if (!passcodePanel) return;
    // Ensure the parent modal is visible so passcodePanel can be interacted with
    if (fileDetailsModal) fileDetailsModal.classList.add('active');
    passcodePanel.style.display = 'block';
    passcodeHelp.textContent = '';
    passcodeInput.value = '';
    passcodeConfirmInput.value = '';

    if (mode === 'create') {
        passcodeTitle.textContent = 'Create master passcode for Hidden Files';
        passcodeConfirmInput.style.display = 'block';
        passcodeSaveBtn.textContent = 'Save';
    } else {
        passcodeTitle.textContent = 'Enter master passcode to access Hidden Files';
        passcodeConfirmInput.style.display = 'none';
        passcodeSaveBtn.textContent = 'Verify';
    }

    passcodeCancelBtn.onclick = () => { closePasscodeUI(); };
    passcodeSaveBtn.onclick = async () => {
        const v = passcodeInput.value.trim();
        if (!v) { passcodeHelp.textContent = 'Passcode cannot be empty.'; return; }

        const key = masterPassKey();

        if (mode === 'create') {
            const confirm = passcodeConfirmInput.value.trim();
            if (v.length < 4) { passcodeHelp.textContent = 'Choose a stronger passcode (min 4 chars).'; return; }
            if (v !== confirm) { passcodeHelp.textContent = 'Passcodes do not match.'; return; }
            const h = await sha256Hex(v);
            localStorage.setItem(key, h);
            closePasscodeUI();
            showToast('Master passcode created.', 'success');
            if (typeof onSuccess === 'function') onSuccess(v);
            return;
        }

        // verify
        const stored = localStorage.getItem(key);
        if (!stored) { passcodeHelp.textContent = 'No master passcode exists. Create one first.'; return; }
        const h = await sha256Hex(v);
        if (h === stored) {
            closePasscodeUI();
            showToast('Master passcode verified.', 'success');
            if (typeof onSuccess === 'function') onSuccess(v);
        } else {
            passcodeHelp.textContent = 'Incorrect passcode. Try again.';
            showToast('Incorrect passcode', 'error');
        }
    };
}

// Render Hidden files (requires master verification to access the page)
function renderHiddenFiles() {
    if (!hiddenFilesGrid) return;
    const list = files.filter(f => f.hidden);
    hiddenFilesGrid.innerHTML = '';

    list.forEach(file => {
        const item = document.createElement('div');
        item.className = 'file-item';
        let iconClass = '';
        switch (file.type) {
            case 'pdf': iconClass = 'pdf'; break;
            case 'docx': iconClass = 'docx'; break;
            case 'xlsx': iconClass = 'xlsx'; break;
            case 'img': iconClass = 'img'; break;
            case 'zip': iconClass = 'blue'; break;
            default: iconClass = 'blue';
        }
        let icon = 'fa-file';
        switch (file.type) {
            case 'pdf': icon = 'fa-file-pdf'; break;
            case 'docx': icon = 'fa-file-word'; break;
            case 'xlsx': icon = 'fa-file-excel'; break;
            case 'img': icon = 'fa-file-image'; break;
            case 'zip': icon = 'fa-file-archive'; break;
            case 'txt': icon = 'fa-file-alt'; break;
        }

        item.innerHTML = `
            <div class="file-icon ${iconClass}">
                <i class="fas ${icon}"></i>
            </div>
            <div class="file-name">${file.name}</div>
            <div class="file-meta">${file.size} â€¢ ${file.date}</div>
            <div class="file-meta">${file.encrypted ? '<i class="fas fa-lock" style="color: #4cc9f0; margin-right: 5px;"></i> Encrypted' : '<i class="fas fa-unlock" style="color: #f8961e; margin-right: 5px;"></i> Not Encrypted'}</div>
            <div class="file-options">
                <button class="view-btn" data-id="${file.id}" title="View"><i class="fas fa-eye"></i></button>
                <button class="share-btn" data-id="${file.id}" title="Share"><i class="fas fa-share-alt"></i></button>
                <button class="encrypt-btn" data-id="${file.id}" title="Toggle Encrypt"><i class="fas fa-lock"></i></button>
                <button class="delete-btn" data-id="${file.id}" title="Delete"><i class="fas fa-trash"></i></button>
            </div>
        `;

        hiddenFilesGrid.appendChild(item);
    });

    attachFileEventListeners();
    try { updateDashboardStats(); } catch (e) { }
}

// Render Recycle Bin contents
function renderTrash() {
    // Reload persisted trash (keeps UI in sync if storage was updated elsewhere)
    try { loadFilesFromStorage(); } catch (e) { }

    // Render both trash grids (on trash page and dashboard)
    const trashGrid = document.getElementById('trashGrid');
    const dashboardTrashGrid = document.getElementById('dashboardTrashGrid');

    if (!trashGrid && !dashboardTrashGrid) return;

    const now = Date.now();

    // Clear both grids
    if (trashGrid) trashGrid.innerHTML = '';
    if (dashboardTrashGrid) dashboardTrashGrid.innerHTML = '';

    if (!trash.length) {
        const emptyMsg = '<div style="padding:20px;color:var(--gray-color);">Recycle Bin is empty.</div>';
        if (trashGrid) trashGrid.innerHTML = emptyMsg;
        if (dashboardTrashGrid) dashboardTrashGrid.innerHTML = emptyMsg;
        try { updateTrashBadge(); } catch (e) { }
        return;
    }

    trash.forEach(item => {
        const el = document.createElement('div');
        el.className = 'file-item';
        const iconClass = (item.type === 'img') ? 'img' : (item.type === 'pdf' ? 'pdf' : 'blue');
        const icon = (item.type === 'pdf') ? 'fa-file-pdf' : (item.type === 'img' ? 'fa-file-image' : 'fa-file');

        const timeLeft = Math.max(0, item.expiresAt - now);
        const mins = Math.floor(timeLeft / 60000);
        const secs = Math.floor((timeLeft % 60000) / 1000);
        const ttl = `${mins}m ${secs}s`;

        el.innerHTML = `
            <div class="file-icon ${iconClass}">
                <i class="fas ${icon}"></i>
            </div>
            <div class="file-name">${item.name}</div>
            <div class="file-meta">${item.size || ''} â€¢ Deleted ${new Date(item.deletedAt).toLocaleString()}</div>
            <div class="file-meta">Expires in: ${ttl}</div>
            <div class="file-options">
                <button class="restore-btn" data-id="${item.id}" title="Restore"><i class="fas fa-undo"></i></button>
                <button class="purge-btn" data-id="${item.id}" title="Delete Permanently"><i class="fas fa-trash"></i></button>
            </div>
        `;

        // Add to both grids
        if (trashGrid) trashGrid.appendChild(el.cloneNode(true));
        if (dashboardTrashGrid) dashboardTrashGrid.appendChild(el);
    });

    // attach handlers for restore / purge
    document.querySelectorAll('.restore-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const id = btn.getAttribute('data-id');
            const idx = trash.findIndex(t => t.id == id);
            if (idx !== -1) {
                const item = trash[idx];
                trash.splice(idx, 1);
                files.unshift(item);
                saveFilesToStorage();
                renderTrash();
                renderFiles();
                renderMyFiles();
                showToast(`"${item.name}" restored`, 'success');
            }
        });
    });

    document.querySelectorAll('.purge-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const id = btn.getAttribute('data-id');
            const idx = trash.findIndex(t => t.id == id);
            if (idx !== -1) {
                const item = trash[idx];
                if (confirm(`Permanently delete "${item.name}"? This cannot be undone.`)) {
                    try { if (item.url) URL.revokeObjectURL(item.url); } catch (e) { }
                    trash.splice(idx, 1);
                    saveFilesToStorage();
                    renderTrash();
                    showToast(`"${item.name}" permanently deleted`, 'success');
                }
            }
        });
    });
    try { updateTrashBadge(); } catch (e) { }
    // Ensure the trash grid is visible near the top of the main content
    try {
        trashGrid.scrollIntoView({ behavior: 'smooth', block: 'start' });
        const main = document.querySelector('.main-content'); if (main) main.scrollTop = Math.max(0, main.scrollTop - 8);
    } catch (e) { }
}


// Handle login
async function handleLogin(e) {
    e.preventDefault();

    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    // Simple validation
    if (!email || !password) {
        showToast('Please fill in all fields', 'error');
        return;
    }

    // Validate against registered user (demo)
    const userRaw = localStorage.getItem('secure_user');
    if (!userRaw) {
        showToast('No registered users found. Please register first.', 'error');
        return;
    }
    const user = JSON.parse(userRaw);
    // check activation
    if (!user.activated) { showToast('Account not activated. Please verify your email.', 'error'); return; }
    const pwHash = await sha256Hex(password);
    if (email === user.email && pwHash === user.passwordHash) {
        // logged in
        currentUserRole = user.role || 'Standard';
        localStorage.setItem('secure_user_role', currentUserRole);
        // Admins require 2FA demo
        if (currentUserRole === 'Administrator') {
            twoFactorRequired = true;
            twoFactorSection.style.display = 'block';
            showToast('Two-factor authentication required for Administrators', 'info');
            return;
        }
        completeLogin();
    } else {
        showToast('Invalid email or password', 'error');
    }
}

// Handle registration
async function handleRegister(e) {
    e.preventDefault();

    const name = document.getElementById('registerName').value;
    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const role = (document.getElementById('registerRole') && document.getElementById('registerRole').value) || 'Standard';

    if (!name || !email || !password || !confirmPassword) {
        showToast('Please fill in all fields', 'error');
        return;
    }

    if (password !== confirmPassword) {
        showToast('Passwords do not match', 'error');
        return;
    }
    // Enforce strong password policy
    const strength = checkPasswordStrength(password);
    if (strength.passed < 4) {
        showToast('Choose a stronger password that meets complexity requirements', 'error');
        return;
    }

    // Create pending user and verification code
    const pwHash = await sha256Hex(password);
    const pending = { name, email, role: role || 'Standard', passwordHash: pwHash, activated: false };
    localStorage.setItem('secure_pending_user', JSON.stringify(pending));
    const code = generateVerificationCode();
    localStorage.setItem('secure_verif_code', code);
    // Show verification modal (demo) and display demo code
    showEmailVerificationModal(code);

    // Reset register form visually (keep pending stored)
    if (registerForm) registerForm.reset();
}

// Verify two-factor code
function verifyTwoFactor() {
    const codeInput = document.getElementById('twoFactorCode');
    if (!codeInput) return;

    const code = codeInput.value;

    if (code.length !== 6 || !/^\d+$/.test(code)) {
        showToast('Please enter a valid 6-digit code', 'error');
        return;
    }

    // For demo purposes, accept any 6-digit code
    if (code.length === 6) {
        completeLogin();
    } else {
        showToast('Invalid verification code', 'error');
    }
}

// Complete the login process
function completeLogin() {
    isAuthenticated = true;
    twoFactorRequired = false;
    authModal.classList.remove('active');
    localStorage.setItem('secureFileAuth', 'true');
    showToast('Login successful! Welcome to SecureFile.', 'success');

    // Reset forms
    if (loginForm) {
        loginForm.reset();
    }
    if (twoFactorSection) {
        twoFactorSection.style.display = 'none';
    }
}

// Theme handling
function applyTheme(theme) {
    try {
        if (theme === 'dark') {
            document.body.classList.add('dark-mode');
            localStorage.setItem('secure_theme', 'dark');
        } else if (theme === 'light') {
            document.body.classList.remove('dark-mode');
            localStorage.setItem('secure_theme', 'light');
        } else {
            // system: clear stored value so default follows system (we'll default to light)
            document.body.classList.remove('dark-mode');
            localStorage.removeItem('secure_theme');
        }
    } catch (e) { }
}

function loadTheme() {
    const t = localStorage.getItem('secure_theme');
    if (t === 'dark') applyTheme('dark');
    else if (t === 'light') applyTheme('light');
    else applyTheme('system');
}

// Account details
function loadAccountDetails() {
    const name = localStorage.getItem('secure_name') || 'John Doe';
    const email = localStorage.getItem('secure_email') || 'admin@securefile.com';
    if (accountNameInput) accountNameInput.value = name;
    if (accountEmailInput) accountEmailInput.value = email;
    // update sidebar
    const avatar = document.querySelector('.user-avatar');
    const userNameEl = document.querySelector('.user-info h4');
    const userEmailEl = document.querySelector('.user-info p');
    if (avatar) avatar.textContent = name.split(' ').map(s => s[0]).slice(0, 2).join('');
    if (userNameEl) userNameEl.textContent = name;
    if (userEmailEl) userEmailEl.textContent = email;
}

function saveAccountDetails() {
    if (!accountNameInput || !accountEmailInput) return;
    const n = accountNameInput.value.trim();
    const e = accountEmailInput.value.trim();
    if (!n || !e) { showToast('Please fill in name and email', 'error'); return; }
    localStorage.setItem('secure_name', n);
    localStorage.setItem('secure_email', e);
    loadAccountDetails();
    showToast('Account details saved', 'success');
}

// Toggle 2FA QR code display
function toggle2FAQRCode() {
    if (enable2FACheckbox && qrCodeContainer) {
        if (enable2FACheckbox.checked) {
            qrCodeContainer.style.display = 'block';
        } else {
            qrCodeContainer.style.display = 'none';
        }
    }
}

// Switch between tabs
function switchTab(tabId) {
    // Update active tab
    tabs.forEach(tab => {
        tab.classList.remove('active');
        if (tab.getAttribute('data-tab') === tabId) {
            tab.classList.add('active');
        }
    });

    // Show active tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });

    const activeTab = document.getElementById(`${tabId}Tab`);
    if (activeTab) {
        activeTab.classList.add('active');
    }
}

// Toggle sidebar on mobile
function toggleSidebar() {
    sidebar.classList.toggle('active');
}

// Show a specific page
function showPage(page) {
    currentPage = page;

    // Hide all pages
    pageContents.forEach(content => {
        content.style.display = 'none';
    });

    // Special handling for Hidden Files page (requires master passcode)
    if (page === 'hidden') {
        // Administrators can access hidden page without master pass
        if (currentUserRole === 'Administrator') {
            hiddenUnlocked = true;
            const pageElement = document.getElementById('hiddenPage');
            if (pageElement) pageElement.style.display = 'block';
            if (pageTitle) pageTitle.textContent = 'Hidden Files';
            renderHiddenFiles();
            return;
        }
        const key = localStorage.getItem(masterPassKey());
        if (!key) {
            // create master then show hidden page
            showMasterPasscodePanel('create', () => {
                hiddenUnlocked = true;
                const pageElement = document.getElementById('hiddenPage');
                if (pageElement) pageElement.style.display = 'block';
                if (pageTitle) pageTitle.textContent = 'Hidden Files';
                renderHiddenFiles();
            });
        } else {
            showMasterPasscodePanel('verify', () => {
                hiddenUnlocked = true;
                const pageElement = document.getElementById('hiddenPage');
                if (pageElement) pageElement.style.display = 'block';
                if (pageTitle) pageTitle.textContent = 'Hidden Files';
                renderHiddenFiles();
            });
        }
        return;
    }

    // Show the selected page
    const pageElement = document.getElementById(`${page}Page`);
    if (pageElement) {
        pageElement.style.display = 'block';
    }

    // Update page title
    const pageTitles = {
        dashboard: 'Dashboard',
        files: 'My Files',
        shared: 'Shared Files',
        trash: 'Recycle Bin',
        security: 'Security Center',
        reports: 'Security Reports',
        settings: 'Settings'
    };

    if (pageTitle) {
        pageTitle.textContent = pageTitles[page] || 'Dashboard';
    }

    // Render content for pages that need it
    if (page === 'dashboard') renderFiles();
    if (page === 'files') renderMyFiles();
    if (page === 'trash') renderTrash();
    // Ensure the main content scroll position is at the top when switching pages
    try { const main = document.querySelector('.main-content'); if (main) main.scrollTop = 0; } catch (e) { }
    // If we navigated to the Recycle Bin, ensure its card/grid is visible at the top
    if (page === 'trash') {
        try {
            const pageEl = document.getElementById('trashPage');
            if (pageEl) pageEl.scrollIntoView({ behavior: 'auto', block: 'start' });
            const grid = document.getElementById('trashGrid'); if (grid) grid.scrollIntoView({ behavior: 'auto', block: 'start' });
            const main = document.querySelector('.main-content'); if (main) main.scrollTop = 0;
        } catch (e) { }
    }
}

// Handle logout
function handleLogout() {
    isAuthenticated = false;
    twoFactorRequired = false;
    authModal.classList.add('active');
    localStorage.removeItem('secureFileAuth');
    showToast('You have been logged out', 'info');
    switchTab('login');
    showPage('dashboard');

    // Reset navigation
    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('data-page') === 'dashboard') {
            link.classList.add('active');
        }
    });
}

// ------------------ Inactivity / Auto-lock ------------------
function setupInactivityDetector() {
    resetInactivityTimer();
    ['click', 'mousemove', 'keydown', 'touchstart'].forEach(evt => {
        document.addEventListener(evt, resetInactivityTimer);
    });
}

function resetInactivityTimer() {
    try { if (inactivityTimer) clearTimeout(inactivityTimer); } catch (e) { }
    inactivityTimer = setTimeout(() => {
        onSessionTimeout();
    }, INACTIVITY_MS);
}

function onSessionTimeout() {
    // Auto logout and lock hidden files
    try {
        hiddenUnlocked = false;
        // log the user out
        handleLogout();
        showToast('Session timed out due to inactivity. Please log in again.', 'info');
    } catch (e) { }
}

// ------------------ Trash cleaner ------------------
function startTrashCleaner() {
    // Run immediately to purge expired items then schedule interval
    try { purgeExpiredTrash(); } catch (e) { }
    if (trashCleanerInterval) clearInterval(trashCleanerInterval);
    trashCleanerInterval = setInterval(() => {
        purgeExpiredTrash();
    }, TRASH_CLEAN_INTERVAL_MS);
}

function purgeExpiredTrash() {
    const now = Date.now();
    let removed = [];
    for (let i = trash.length - 1; i >= 0; i--) {
        const item = trash[i];
        if (item.expiresAt && now >= item.expiresAt) {
            try { if (item.url) URL.revokeObjectURL(item.url); } catch (e) { }
            removed.push(item);
            trash.splice(i, 1);
        }
    }
    if (removed.length) {
        saveFilesToStorage();
        try { renderTrash(); } catch (e) { }
        showToast(`${removed.length} item(s) permanently removed from Recycle Bin`, 'info');
    }
}

// Permission checking helper
function checkPermission(file, permissionType) {
    if (!file.permissions) {
        // If no permissions object, allow everything (backwards compatibility)
        return true;
    }

    const permMap = {
        'view': file.permissions.view,
        'download': file.permissions.download,
        'edit': file.permissions.edit,
        'delete': file.permissions.canDelete
    };

    return permMap[permissionType] === true;
}

function showPermissionDenied(action) {
    showToast(`Permission Denied: You don't have permission to ${action} this file`, 'error');
}

// Show upload permissions modal and return selected permissions
function showUploadPermissionsModal(fileName) {
    return new Promise((resolve, reject) => {
        const modal = document.getElementById('uploadPermissionsModal');
        const fileNameEl = document.getElementById('uploadFileName');
        const confirmBtn = document.getElementById('confirmUploadPermissions');
        const cancelBtn = document.getElementById('cancelUploadPermissions');

        if (!modal) {
            resolve({ view: true, download: true, edit: true, canDelete: true });
            return;
        }

        fileNameEl.textContent = fileName;
        modal.classList.add('active');

        const handleConfirm = () => {
            const permissions = {
                view: document.getElementById('permView')?.checked || false,
                download: document.getElementById('permDownload')?.checked || false,
                edit: document.getElementById('permEdit')?.checked || false,
                canDelete: document.getElementById('permDelete')?.checked || false
            };
            modal.classList.remove('active');
            confirmBtn.removeEventListener('click', handleConfirm);
            cancelBtn.removeEventListener('click', handleCancel);
            resolve(permissions);
        };

        const handleCancel = () => {
            modal.classList.remove('active');
            confirmBtn.removeEventListener('click', handleConfirm);
            cancelBtn.removeEventListener('click', handleCancel);
            reject('cancelled');
        };

        confirmBtn.addEventListener('click', handleConfirm);
        cancelBtn.addEventListener('click', handleCancel);
    });
}

// Handle file upload
function handleUpload() {
    // Secure upload: encrypt files client-side using master passphrase (AES-GCM)
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.multiple = true;

    fileInput.onchange = async (e) => {
        if (!e.target.files.length) return;

        const selections = Array.from(e.target.files);

        // Check encryption mode from dropdown
        const encryptionModeSelect = document.getElementById('uploadEncryptionMode');
        const shouldEncrypt = encryptionModeSelect ? (encryptionModeSelect.value === 'encrypted') : true;

        // Read buffers
        const buffers = [];
        for (let f of selections) {
            try {
                const ab = await f.arrayBuffer();
                buffers.push({ file: f, buffer: ab });
            } catch (err) {
                showToast(`Failed to read ${f.name}`, 'error');
            }
        }

        // Process files directly without master passcode requirement
        // For each file: prompt for a per-file passcode, derive per-file key, encrypt, compute integrity hash, run malware scan
        const signatures = ['virus', 'malware', 'trojan', 'worm'];

        for (let i = 0; i < buffers.length; i++) {
            const { file, buffer } = buffers[i];
            const fileName = file.name;
            const fileExt = fileName.split('.').pop().toLowerCase();
            let fileType = 'txt';
            if (['pdf'].includes(fileExt)) fileType = 'pdf';
            else if (['docx', 'doc'].includes(fileExt)) fileType = 'docx';
            else if (['xlsx', 'xls'].includes(fileExt)) fileType = 'xlsx';
            else if (['jpg', 'jpeg', 'png', 'gif'].includes(fileExt)) fileType = 'img';
            else if (['zip', 'rar'].includes(fileExt)) fileType = 'zip';
            else if (['txt'].includes(fileExt)) fileType = 'txt';

            const integrity = await sha256Buffer(buffer);

            // malware scan (simple text-based signature matching)
            let malwareFound = false;
            try {
                const text = new TextDecoder().decode(buffer);
                const lower = text.toLowerCase();
                for (const sig of signatures) {
                    if (lower.includes(sig)) { malwareFound = true; break; }
                }
            } catch (e) {
                // binary files may fail to decode - skip
            }

            // Prepare a temporary file object with an id so showPasscodePanel can store pass hash
            const provisionalId = files.length + 1 + i;
            const tempFile = { id: provisionalId, name: fileName };

            let passphrase = null;
            let encryptedData = null;
            let iv = null;
            let salt = null;

            // Only ask for passcode and encrypt if user selected encrypted mode
            if (shouldEncrypt) {
                // Ask the user to create a passcode for this file
                passphrase = await askPasscodeForFile('create', tempFile);
                if (!passphrase) {
                    showToast(`Skipping ${fileName}: no passcode provided`, 'info');
                    continue;
                }

                const saltBytes = getRandomSalt();
                const key = await deriveKeyFromPassword(passphrase, saltBytes);
                const enc = await encryptBuffer(key, buffer);

                encryptedData = enc.data;
                iv = enc.iv;
                salt = arrayBufferToBase64(saltBytes.buffer);
            }

            // Ask for file permissions
            let filePermissions;
            try {
                filePermissions = await showUploadPermissionsModal(fileName);
            } catch (err) {
                showToast(`Skipping ${fileName}: permissions not set`, 'info');
                continue;
            }

            const newFile = {
                id: provisionalId,
                name: fileName,
                type: fileType,
                size: `${(file.size / 1024 / 1024).toFixed(1)} MB`,
                date: new Date().toISOString().split('T')[0],
                encrypted: shouldEncrypt,
                encryptedData: encryptedData,
                iv: iv,
                salt: salt,
                integrityHash: integrity,
                malware: malwareFound,
                role: 'Owner',
                permissions: filePermissions,
                originalExt: fileExt,
                originalMime: file.type
            };

            files.unshift(newFile);
        }

        saveFilesToStorage();
        renderFiles();
        const uploadType = shouldEncrypt ? 'encrypted' : 'uploaded';
        showToast(`${buffers.length} file(s) ${uploadType} successfully`, 'success');
    };

    fileInput.click();
}

// Show toast notification
function showToast(message, type = 'success') {
    if (!toast || !toastMessage) return;

    toastMessage.textContent = message;
    toast.className = 'toast';

    // Set type-specific styles
    if (type === 'success') {
        toast.classList.add('toast-success');
        toast.querySelector('i').className = 'fas fa-check-circle';
    } else if (type === 'error') {
        toast.classList.add('toast-error');
        toast.querySelector('i').className = 'fas fa-exclamation-circle';
    } else if (type === 'info') {
        toast.querySelector('i').className = 'fas fa-info-circle';
    }

    // Show toast
    toast.classList.add('show');

    // Hide after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', init);

// Close sidebar when clicking outside on mobile
document.addEventListener('click', (e) => {
    if (window.innerWidth < 992 &&
        !sidebar.contains(e.target) &&
        !mobileMenuBtn.contains(e.target) &&
        sidebar.classList.contains('active')) {
        sidebar.classList.remove('active');
    }
});

// Handle escape key to close sidebar
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && sidebar.classList.contains('active')) {
        sidebar.classList.remove('active');
    }
});
