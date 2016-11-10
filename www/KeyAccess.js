var exec = require('cordova/exec');

module.exports = {
getPublicKey: function(arg0,successCallback,failCallback)
    {
         exec(successCallback, failCallback, "KeyAccess", "getPublicKey", [arg0]);
    },
    
    geneSigning: function(arg0,successCallback,failCallback)
    
    {
         var strToenc=arg0.strToEnc;
         
         exec(successCallback, failCallback, "KeyAccess", "geneSigning", [strToenc]);
    },
    
     deleteMethod: function(arg0,successCallback,failCallback)
    {
         
         exec(successCallback, failCallback, "KeyAccess", "deleteMethod", [arg0]);
    }
};