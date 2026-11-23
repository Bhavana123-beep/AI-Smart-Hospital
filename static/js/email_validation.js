(() => {
  "use strict";

  // Keep this expression in sync with app.py's is_valid_email().
  const emailPattern = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  const patientIdPattern = /^PAT-\d+$/i;

  document.querySelectorAll('form input[name="email"]').forEach((input) => {
    const form = input.form;
    if (!form) return;

    const normalize = () => {
      input.value = input.value.trim().toLowerCase();
      input.setCustomValidity("");
    };

    input.addEventListener("blur", normalize);
    input.addEventListener("input", () => input.setCustomValidity(""));
    form.addEventListener("submit", (event) => {
      normalize();
      const value = input.value;
      const legacyPatientId = input.dataset.allowPatientId === "true" && patientIdPattern.test(value);
      if (!legacyPatientId && !emailPattern.test(value)) {
        input.setCustomValidity("Enter a valid email address.");
        input.reportValidity();
        event.preventDefault();
      }
    });
  });
})();
