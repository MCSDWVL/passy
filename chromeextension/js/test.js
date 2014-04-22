chrome.browserAction.onClicked.addListener(function (tab)
{
	// No tabs or host permissions needed!
	//alert(tab.url);
	chrome.tabs.executeScript({
		code: 'document.activeElement.value = "test"; alert("here we are " + document.activeElement.value);'
	});
});