// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
  });
});

// Simulate dropdown toggles
document.querySelectorAll('.branch-btn, .add-file-btn, .code-btn, .contribute-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    btn.style.opacity = '0.7';
    setTimeout(() => { btn.style.opacity = '1'; }, 150);
  });
});
