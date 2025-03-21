// Toggle between light and dark mode
document.addEventListener('DOMContentLoaded', function() {
  const toggleButton = document.getElementById('theme-toggle');
  if(toggleButton) {
    toggleButton.addEventListener('click', function() {
      const htmlEl = document.documentElement;
      if(htmlEl.getAttribute('data-theme') === 'dark'){
          htmlEl.setAttribute('data-theme', 'light');
      } else {
          htmlEl.setAttribute('data-theme', 'dark');
      }
      // Optionally, send an AJAX request to save the preference
    });
  }
});
