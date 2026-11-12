// Runs only in browsers without ES module support (Internet Explorer). ES5 only.
(function () {
  var app = document.getElementById('app');
  if (!app) return;
  app.innerHTML = '';
  var box = document.createElement('div');
  box.className = 'boot';
  var p1 = document.createElement('p');
  p1.appendChild(document.createTextNode('Internet Explorer ไม่รองรับหน้านี้ กรุณาเปิดด้วย Microsoft Edge หรือ Google Chrome'));
  var p2 = document.createElement('p');
  p2.appendChild(document.createTextNode('Internet Explorer is not supported. Please use Microsoft Edge or Google Chrome.'));
  box.appendChild(p1);
  box.appendChild(p2);
  app.appendChild(box);
})();
