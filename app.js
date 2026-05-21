/**
 * app.js — Hash Engine UI (v5)
 *
 * - Aucun hash affiché à l'écran
 * - Copie silencieuse dans le presse-papiers au clic GO
 * - Aucun message de confirmation visible (discrétion totale)
 * - Barre d'entropie mise à jour après génération
 * - Bouton GO désactivé si les 3 champs obligatoires sont vides
 */

document.addEventListener('DOMContentLoaded', () => {

  // ── DOM ────────────────────────────────────────────────────────────────────

  const inputField           = document.getElementById('userInput');
  const saltField            = document.getElementById('saltInput');
  const pepperField          = document.getElementById('pepperInput');
  const specialCharsToggle   = document.getElementById('specialCharsToggle');

  const generateBtn          = document.getElementById('generateButton');
  const loadingSpinner       = document.getElementById('loadingSpinner');
  const btnText              = document.getElementById('btnText');

  const toggleInputVis       = document.getElementById('toggleInputVisibility');
  const toggleSaltVis        = document.getElementById('toggleSaltVisibility');
  const togglePepperVis      = document.getElementById('togglePepperVisibility');
  const generatePepperBtn    = document.getElementById('generatePepperBtn');

  const entropyBar           = document.getElementById('entropyBar');
  const entropyFill          = document.getElementById('entropyFill');
  const entropyLabel         = document.getElementById('entropyLabel');

  // ── État ───────────────────────────────────────────────────────────────────

  let isGenerating = false;

  // ── Validation ─────────────────────────────────────────────────────────────

  function isFormValid() {
    return (
        inputField.value.trim().length  > 0 &&
        saltField.value.trim().length   > 0 &&
        pepperField.value.trim().length > 0
    );
  }

  function updateButtonState() {
    generateBtn.disabled = isGenerating || !isFormValid();
  }

  // ── Barre d'entropie ───────────────────────────────────────────────────────

  const STRENGTH_LEVELS = [
    { max: 20,  label: 'Very Weak',  color: '#ef4444' },
    { max: 40,  label: 'Weak',       color: '#f97316' },
    { max: 60,  label: 'Moderate',   color: '#eab308' },
    { max: 80,  label: 'Strong',     color: '#22c55e' },
    { max: 100, label: 'Very Strong',color: '#10b981' },
  ];

  /**
   * Met à jour la barre d'entropie avec le score donné (0-100).
   * @param {number} score
   */
  function updateEntropyBar(score) {
    const level = STRENGTH_LEVELS.find(l => score <= l.max) || STRENGTH_LEVELS.at(-1);

    entropyFill.style.width       = score + '%';
    entropyFill.style.background  = level.color;
    entropyLabel.textContent      = level.label;
    entropyLabel.style.color      = level.color;

    entropyBar.classList.remove('hidden');
  }

  function resetEntropyBar() {
    entropyBar.classList.add('hidden');
    entropyFill.style.width = '0%';
    entropyLabel.textContent = '';
  }

  // ── Toggle visibilité ──────────────────────────────────────────────────────

  /**
   * Bascule entre type="password" et type="text" sur un champ.
   * @param {HTMLInputElement} field
   * @param {HTMLButtonElement} btn
   */
  function toggleVisibility(field, btn) {
    const isHidden = field.type === 'password';
    field.type    = isHidden ? 'text'     : 'password';
    btn.textContent = isHidden ? '🙈'    : '👁️';
    btn.title      = isHidden ? 'Hide'   : 'Show';
  }

  // ── Génération de clé aléatoire ────────────────────────────────────────────

  generatePepperBtn.addEventListener('click', () => {
    pepperField.value   = SecureHasher.generateRandomKey(32);
    pepperField.type    = 'text';
    togglePepperVis.textContent = '🙈';
    togglePepperVis.title       = 'Hide';

    // Masquer la clé après 3 secondes
    setTimeout(() => {
      pepperField.type            = 'password';
      togglePepperVis.textContent = '👁️';
      togglePepperVis.title       = 'Show';
    }, 3000);

    updateButtonState();
  });

  // ── Listeners visibilité ───────────────────────────────────────────────────

  toggleInputVis.addEventListener('click',  () => toggleVisibility(inputField,  toggleInputVis));
  toggleSaltVis.addEventListener('click',   () => toggleVisibility(saltField,   toggleSaltVis));
  togglePepperVis.addEventListener('click', () => toggleVisibility(pepperField, togglePepperVis));

  // ── Listeners champs ───────────────────────────────────────────────────────

  [inputField, saltField, pepperField].forEach(f => {
    f.addEventListener('input', () => {
      resetEntropyBar();
      updateButtonState();
    });
  });

  specialCharsToggle.addEventListener('change', () => {
    resetEntropyBar();
    updateButtonState();
  });

  // Soumission par Entrée
  [inputField, saltField, pepperField].forEach(f => {
    f.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !generateBtn.disabled) generateBtn.click();
    });
  });

  // ── Copie silencieuse ──────────────────────────────────────────────────────

  /**
   * Copie un texte dans le presse-papiers sans afficher de notification.
   * Tente d'abord l'API moderne, puis le fallback execCommand.
   * @param {string} text
   * @returns {Promise<void>}
   */
  async function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }
    // Fallback discret
    const ta = document.createElement('textarea');
    ta.value = text;
    Object.assign(ta.style, {
      position  : 'fixed',
      top       : '-9999px',
      left      : '-9999px',
      opacity   : '0',
      tabIndex  : '-1',
    });
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  }

  // ── État du bouton pendant la génération ───────────────────────────────────

  function setLoading(loading) {
    isGenerating = loading;

    if (loading) {
      generateBtn.disabled = true;
      loadingSpinner.classList.remove('hidden');
      btnText.textContent = 'WAIT';
    } else {
      loadingSpinner.classList.add('hidden');
      btnText.textContent = 'GO';
      updateButtonState();
    }
  }

  // ── Action GO ─────────────────────────────────────────────────────────────

  generateBtn.addEventListener('click', async () => {
    if (isGenerating || generateBtn.disabled) return;

    const input     = inputField.value;
    const salt      = saltField.value;
    const secretKey = pepperField.value;
    const addSpec   = specialCharsToggle.checked;

    setLoading(true);

    try {
      // Petit délai pour que le spinner soit visible avant le calcul PBKDF2
      await new Promise(resolve => setTimeout(resolve, 80));

      const { hash, score } = await SecureHasher.generateSecureHash(
          input, salt, secretKey, addSpec
      );

      // Copie silencieuse — aucun affichage du hash
      await copyToClipboard(hash);

      // Mise à jour de la barre d'entropie
      updateEntropyBar(score);

      // Feedback visuel minimal sur le bouton (couleur seulement, pas de texte révélateur)
      generateBtn.classList.add('success');

      setTimeout(() => {
        generateBtn.classList.remove('success');
        setLoading(false);
      }, 1500);

    } catch (_err) {
      // Échec silencieux — on remet juste le bouton dans son état normal
      setLoading(false);
      resetEntropyBar();
    }
  });

  // ── Init ───────────────────────────────────────────────────────────────────

  // Checkbox cochée par défaut : les caractères spéciaux sont activés au démarrage
  specialCharsToggle.checked = true;

  resetEntropyBar();
  updateButtonState();

});
