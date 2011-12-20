//Based on code from: https://www.axolotlfarm.org/svn/bergi/bergnet/php/certbuilder/trunk/explorer-keygen.js
//Author: bergi@axolotlfarm.org>
//License: MIT

ExplorerKeygen = {};

// X509Enrollment documentation at MSDN
// http://msdn.microsoft.com/en-us/library/windows/desktop/aa377863%28v=vs.85%29.aspx
ExplorerKeygen.createCsr = function (keyLength) {

	try {
		this.enrollmentFactory = new ActiveXObject("X509Enrollment.CX509EnrollmentWebClassFactory");
	} catch (e) {
		///XXX we should give more help to the user here.
		//some pictures like:
		//http://surfthenetsafely.com/ieseczone7.htm
		//XXX Other option would be to download a .REG file that does that ;)
		alert("you have to add this website to the list of trusted sites in the internet-settings. Go to Internet Options->Security->Trusted Websites, click on Custom Level, check ActiveX control elements that are not marked as safe initialized on start in scripts");
	}
	var privateKey = this.enrollmentFactory.CreateObject("X509Enrollment.CX509PrivateKey");
	privateKey.ProviderType = 24;
	privateKey.KeySpec = 1;
	privateKey.Length = keyLength;
	privateKey.MachineContext = false;
	privateKey.KeyProtection = 1;
	privateKey.ExportPolicy = 1;

	var csr = this.enrollmentFactory.CreateObject("X509Enrollment.CX509CertificateRequestPkcs10");
	csr.InitializeFromPrivateKey(1, privateKey, "");

	this.enrollment = this.enrollmentFactory.CreateObject("X509Enrollment.CX509Enrollment");
	this.enrollment.InitializeFromRequest(csr);

	var csrString = this.enrollment.CreateRequest(1);

	csrString = "-----BEGIN IE CERTIFICATE REQUEST-----\n" + csrString + "-----END IE CERTIFICATE REQUEST-----\n";

	return csrString;
}

ExplorerKeygen.installCertificate = function(certificate) {
	try {
		//alert('trying to install the certificate');
		//alert('certdata=' + certificate);
		this.enrollment.InstallResponse(4, certificate, 6, "");
		alert("A certificate has been installed.");
	} catch (e1) {
		try {
			//alert('first thing did not work');
			this.enrollment.InstallResponse(0, certificate, 6, "");
			alert("A certificate has been installed.");
		} catch (e2) {
			alert("You're probably using Vista without SP1 (or above), in which case you need to add the certificate of this authority as a trusted root certificate (not recommended in general).");
		}
	}
}


ExplorerKeygen.prepareForm = function(form) {
	//XXX FIXME this is dupping the data :/
	$(form).find("keygen").each(function(keygenIndex, keygen) {
		// create key length combobox
		var keyLengthCombobox = $("<select><option label=\"1024 bit\" value=\"1024\" selected=\"selected\" /><option label=\"2048 bit\" value=\"2048\" /></select>");
		$(keygen).after(keyLengthCombobox);

		// create keylength attribute
		$(keygen).attr("keylength", "1024");

		// add change event handler
		$(keyLengthCombobox).change(function() {
			$(keygen).attr("keylength", $(this).val());
		});
	});
	$(form).find("input[type='submit']").each(function(submitIndex, submit) {
		// read class, style and value ...
		var cssClass = $(submit).attr("class");
		var style = $(submit).attr("style");
		var value = $(submit).attr("value");

		// .. for alternative submit button ...
		var altSubmit = $("<input type=\"button\" class=\"" + cssClass + "\" value=\"" + value + "\" style=\"" + style + "\" />");

		// ... and add it after the original submit button ...
		$(submit).after(altSubmit);

		// ... which we remove now
		$(submit).remove();

		// add click event handler to alternative submit button
		$(altSubmit).click(function() { ExplorerKeygen.submitForm(form) });
	});

	// save original action in ekaction ...
	$(form).attr("ekaction", $(form).attr("action"));

	// ... and remove action and method attribute
	$(form).removeAttr("action");
	$(form).removeAttr("method");
}


ExplorerKeygen.submitForm = function(form) {
	$(form).find("keygen").each(function(keygenIndex, keygen) {
		// read keylength attribute from keygen element
		var keyLength = $(keygen).attr("keylength");

		// create certificate signing request
		var csr = ExplorerKeygen.createCsr(keyLength);

		// read name attribute from keygen element ...
		var name = $(keygen).attr("name");

		// ... and create a hidden input field with the same name and store the csr
		$(keygen).after("<input type=\"hidden\" name=\"" + name + "\" value=\"" + csr + "\" />");

		// get the serialized form data
		var formData = $(form).serialize();

		// read the original action from the ekaction attribute
		var formAction = $(form).attr("ekaction");

		// if action is empty send request to document url
		if(formAction == "")
			formAction = document.URL;

		// finally send the request 
		$.ajax({
			type: "POST",
			url: formAction,
			data: formData,
			success: function(certificate) { ExplorerKeygen.installCertificate(certificate); },
			error: function(dummy, error) { alert("error: " + error); }
		});
	});
}


$(document).ready(function() {
	$("form").each(function(index, form) { ExplorerKeygen.prepareForm(form); });
});
