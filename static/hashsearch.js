function _(el) {
  return document.getElementById(el);
}

function uploadFile() {
  var file = _("file").files[0];
  var formdata = new FormData();
  formdata.append("file", file);
  var ajax = new XMLHttpRequest();
  ajax.upload.addEventListener("progress", progressHandler, false);
  ajax.addEventListener("load", completeHandler, false);
  ajax.addEventListener("error", errorHandler, false);
  ajax.addEventListener("abort", abortHandler, false);
  ajax.open("POST", "/hashlist");
  ajax.send(formdata);
}

function progressHandler(event) {
  _("loaded_n_total").innerHTML = "Uploaded " + event.loaded + " bytes of " + event.total;
  var percent = (event.loaded / event.total) * 100;
  _("progressBar").value = Math.round(percent);
  _("status").innerHTML = Math.round(percent) + "% uploaded.";
}

function completeHandler(event) {
  _("status").innerHTML = "Uploded Successfully!";
  _("progressBar").value = 0; //wil clear progress bar after successful upload
  _("loaded_n_total").innerHTML = "" ;
  setTimeout('', 5000);
  window.location.href = '/search';
}

function errorHandler(event) {
  _("status").innerHTML = "Upload Failed";
}

function abortHandler(event) {
  _("status").innerHTML = "Upload Aborted";
}