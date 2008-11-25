/// <reference path="minilib.js">
/// <reference path="xml.js">
/// <reference path="xmlrpc.js">
/// <reference path="tools.js">
pom.dialog = function() {this._showing = false };

function get_page_width() {
	/// <returns type="Number">width of page in pixels</returns>
	var frameWidth;
	if (self.innerWidth) {
		frameWidth = self.innerWidth;
	} else if (document.documentElement && document.documentElement.clientWidth) {
		frameWidth = document.documentElement.clientWidth;
	} else if (document.body) {
		frameWidth = document.body.clientWidth;
	}
	return frameWidth;
}
function get_page_height() {
	/// <returns type="Number">height of page in pixels</returns>
	var frameHeight;
	if (self.innerHeight) {
		frameHeight = self.innerHeight;
	} else if (document.documentElement && document.documentElement.clientHeight) {
		frameHeight = document.documentElement.clientHeight;
	} else if (document.body) {
		frameHeight = document.body.clientHeight;
	}
	return frameHeight;
}
function get_scroll_xy() {
	/// <summary>Returns how far the browser is currently scrolled</summary>
	/// <returns type="Array">first element is x offset, second is y</returns>
	var x, y;
	if (self.pageYOffset) // all except Explorer
	{
		x = self.pageXOffset;
		y = self.pageYOffset;
	}
	else if (document.documentElement && document.documentElement.scrollTop)
	// Explorer 6 Strict
	{
		x = document.documentElement.scrollLeft;
		y = document.documentElement.scrollTop;
	}
	else if (document.body) // all other Explorers
	{
		x = document.body.scrollLeft;
		y = document.body.scrollTop;
	}
	return [x, y];
}
pom.dialog.onload = function() {
	this._dialog_div = document.createElement("div");
	this._dialog_div.className = "dialog_div";
	this._content_div = $E("div");
	this._content_div.className = "dialog_content";
	this._content_holder = $E("div");
	this._content_holder.className = "dialog_holder";
	this._content_div.appendChild(this._content_holder);
	this._dialog_div.appendChild(this._content_div);
	Element.hide(this._dialog_div);
	document.body.appendChild(this._dialog_div);
};
pom.dialog.re_center = function() {
	if (!this._showing)
		return;
	var width = Element.getWidth(this._content_div);
	var height = Element.getHeight(this._content_div);
	var xy = get_scroll_xy();
	this._content_div.style.left = (xy[0] + ((get_page_width() / 2) - width / 2)) + "px";
	this._content_div.style.top = (xy[1] + ((get_page_height() / 2) - height / 2)) + "px";
};
pom.dialog.create = function(dom_element) {
	this._dialog_div.style.width = get_page_width() + "px";
	this._dialog_div.style.height = get_page_height() + "px";
	Element.show(this._dialog_div);
	this._content_holder.innerHTML = "";
	this._content_holder.appendChild(dom_element);
	this._showing = true;
	this.re_center();
};
pom.dialog.done = function() {
	this._showing = false;
	Element.hide(this._dialog_div);
};