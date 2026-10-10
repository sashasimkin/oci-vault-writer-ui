'use strict';

document.body.addEventListener('htmx:afterRequest', (event) => {
  const form = event.detail.elt;
  if (form instanceof HTMLFormElement && form.matches('[hx-post="/api/write"]')) {
    form.querySelector('[name="value"]').value = '';
  }
});
