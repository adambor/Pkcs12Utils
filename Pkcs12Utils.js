import forge from "node-forge";

class Pkcs12Utils {

    static isValid(certData, password) {
        try {
            var p12Der = forge.util.decode64(certData);
            var p12Asn1 = forge.asn1.fromDer(p12Der);
            var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);
            var bags = p12.getBags({ bagType: forge.pki.oids.certBag});
            var certs = bags[forge.pki.oids.certBag];

            const now = new Date();

            let minExpiryDays = Number.MAX_VALUE;
            for(let cert of certs) {
                const diff = cert.cert.validity.notAfter.getTime()-now.getTime();
                const daysTillExpiry = Math.floor(diff/(1000*60*60*24));
                minExpiryDays = Math.min(minExpiryDays, daysTillExpiry);
            }
            return minExpiryDays;
        } catch (e) {
            console.log(e);
            return null;
        }
    }

    static getExpiryDate(certData, password) {
        try {
            var p12Der = forge.util.decode64(certData);
            var p12Asn1 = forge.asn1.fromDer(p12Der);
            var p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);
            var bags = p12.getBags({ bagType: forge.pki.oids.certBag});
            var certs = bags[forge.pki.oids.certBag];

            let expiryDate;
            for(let cert of certs) {
                expiryDate = cert.cert.validity.notAfter;
            }
            return expiryDate;
        } catch (e) {
            console.log(e);
            return null;
        }
    }

}

export default Pkcs12Utils;