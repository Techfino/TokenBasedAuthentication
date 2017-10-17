/**
 * @NApiVersion 2.x
 */

/******************************************************************************************
 * Copyright (c) 2014-2016 Techfino, LLC
 * 2020 Federal Street, Philadelphia, PA 19146, USA
 * All Rights Reserved.
 *
 * This software is the confidential and proprietary information of Techfino LLC.  
 * ("Confidential Information") - You shall not disclose such Confidential Information 
 * without prior written permission.
 *
 * Script Description: 
 *  This script is the central library for webservices functions for Techfino SS 2.0
 ******************************************************************************************/

define(['N/error', 'N/https', 'N/xml', 'N/runtime'],
    function(error, https, xml, runtime) {

        /*
        CryptoJS v3.1.2
        code.google.com/p/crypto-js
        (c) 2009-2013 by Jeff Mott. All rights reserved.
        code.google.com/p/crypto-js/wiki/License
        */
        var CryptoJS=CryptoJS||function(g,l){var e={},d=e.lib={},m=function(){},k=d.Base={extend:function(a){m.prototype=this;var c=new m;a&&c.mixIn(a);c.hasOwnProperty("init")||(c.init=function(){c.$super.init.apply(this,arguments)});c.init.prototype=c;c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.init.prototype.extend(this)}},
        p=d.WordArray=k.extend({init:function(a,c){a=this.words=a||[];this.sigBytes=c!=l?c:4*a.length},toString:function(a){return(a||n).stringify(this)},concat:function(a){var c=this.words,q=a.words,f=this.sigBytes;a=a.sigBytes;this.clamp();if(f%4)for(var b=0;b<a;b++)c[f+b>>>2]|=(q[b>>>2]>>>24-8*(b%4)&255)<<24-8*((f+b)%4);else if(65535<q.length)for(b=0;b<a;b+=4)c[f+b>>>2]=q[b>>>2];else c.push.apply(c,q);this.sigBytes+=a;return this},clamp:function(){var a=this.words,c=this.sigBytes;a[c>>>2]&=4294967295<<
        32-8*(c%4);a.length=g.ceil(c/4)},clone:function(){var a=k.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var c=[],b=0;b<a;b+=4)c.push(4294967296*g.random()|0);return new p.init(c,a)}}),b=e.enc={},n=b.Hex={stringify:function(a){var c=a.words;a=a.sigBytes;for(var b=[],f=0;f<a;f++){var d=c[f>>>2]>>>24-8*(f%4)&255;b.push((d>>>4).toString(16));b.push((d&15).toString(16))}return b.join("")},parse:function(a){for(var c=a.length,b=[],f=0;f<c;f+=2)b[f>>>3]|=parseInt(a.substr(f,
        2),16)<<24-4*(f%8);return new p.init(b,c/2)}},j=b.Latin1={stringify:function(a){var c=a.words;a=a.sigBytes;for(var b=[],f=0;f<a;f++)b.push(String.fromCharCode(c[f>>>2]>>>24-8*(f%4)&255));return b.join("")},parse:function(a){for(var c=a.length,b=[],f=0;f<c;f++)b[f>>>2]|=(a.charCodeAt(f)&255)<<24-8*(f%4);return new p.init(b,c)}},h=b.Utf8={stringify:function(a){try{return decodeURIComponent(escape(j.stringify(a)))}catch(c){throw Error("Malformed UTF-8 data");}},parse:function(a){return j.parse(unescape(encodeURIComponent(a)))}},
        r=d.BufferedBlockAlgorithm=k.extend({reset:function(){this._data=new p.init;this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=h.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var c=this._data,b=c.words,f=c.sigBytes,d=this.blockSize,e=f/(4*d),e=a?g.ceil(e):g.max((e|0)-this._minBufferSize,0);a=e*d;f=g.min(4*a,f);if(a){for(var k=0;k<a;k+=d)this._doProcessBlock(b,k);k=b.splice(0,a);c.sigBytes-=f}return new p.init(k,f)},clone:function(){var a=k.clone.call(this);
        a._data=this._data.clone();return a},_minBufferSize:0});d.Hasher=r.extend({cfg:k.extend(),init:function(a){this.cfg=this.cfg.extend(a);this.reset()},reset:function(){r.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);return this._doFinalize()},blockSize:16,_createHelper:function(a){return function(b,d){return(new a.init(d)).finalize(b)}},_createHmacHelper:function(a){return function(b,d){return(new s.HMAC.init(a,
        d)).finalize(b)}}});var s=e.algo={};return e}(Math);
        (function(){var g=CryptoJS,l=g.lib,e=l.WordArray,d=l.Hasher,m=[],l=g.algo.SHA1=d.extend({_doReset:function(){this._hash=new e.init([1732584193,4023233417,2562383102,271733878,3285377520])},_doProcessBlock:function(d,e){for(var b=this._hash.words,n=b[0],j=b[1],h=b[2],g=b[3],l=b[4],a=0;80>a;a++){if(16>a)m[a]=d[e+a]|0;else{var c=m[a-3]^m[a-8]^m[a-14]^m[a-16];m[a]=c<<1|c>>>31}c=(n<<5|n>>>27)+l+m[a];c=20>a?c+((j&h|~j&g)+1518500249):40>a?c+((j^h^g)+1859775393):60>a?c+((j&h|j&g|h&g)-1894007588):c+((j^h^
        g)-899497514);l=g;g=h;h=j<<30|j>>>2;j=n;n=c}b[0]=b[0]+n|0;b[1]=b[1]+j|0;b[2]=b[2]+h|0;b[3]=b[3]+g|0;b[4]=b[4]+l|0},_doFinalize:function(){var d=this._data,e=d.words,b=8*this._nDataBytes,g=8*d.sigBytes;e[g>>>5]|=128<<24-g%32;e[(g+64>>>9<<4)+14]=Math.floor(b/4294967296);e[(g+64>>>9<<4)+15]=b;d.sigBytes=4*e.length;this._process();return this._hash},clone:function(){var e=d.clone.call(this);e._hash=this._hash.clone();return e}});g.SHA1=d._createHelper(l);g.HmacSHA1=d._createHmacHelper(l)})();
        (function(){var g=CryptoJS,l=g.enc.Utf8;g.algo.HMAC=g.lib.Base.extend({init:function(e,d){e=this._hasher=new e.init;"string"==typeof d&&(d=l.parse(d));var g=e.blockSize,k=4*g;d.sigBytes>k&&(d=e.finalize(d));d.clamp();for(var p=this._oKey=d.clone(),b=this._iKey=d.clone(),n=p.words,j=b.words,h=0;h<g;h++)n[h]^=1549556828,j[h]^=909522486;p.sigBytes=b.sigBytes=k;this.reset()},reset:function(){var e=this._hasher;e.reset();e.update(this._iKey)},update:function(e){this._hasher.update(e);return this},finalize:function(e){var d=
        this._hasher;e=d.finalize(e);d.reset();return d.finalize(this._oKey.clone().concat(e))}})})();
        
        /*
        CryptoJS v3.1.2
        code.google.com/p/crypto-js
        (c) 2009-2013 by Jeff Mott. All rights reserved.
        code.google.com/p/crypto-js/wiki/License
        */
        (function(){var h=CryptoJS,j=h.lib.WordArray;h.enc.Base64={stringify:function(b){var e=b.words,f=b.sigBytes,c=this._map;b.clamp();b=[];for(var a=0;a<f;a+=3)for(var d=(e[a>>>2]>>>24-8*(a%4)&255)<<16|(e[a+1>>>2]>>>24-8*((a+1)%4)&255)<<8|e[a+2>>>2]>>>24-8*((a+2)%4)&255,g=0;4>g&&a+0.75*g<f;g++)b.push(c.charAt(d>>>6*(3-g)&63));if(e=c.charAt(64))for(;b.length%4;)b.push(e);return b.join("")},parse:function(b){var e=b.length,f=this._map,c=f.charAt(64);c&&(c=b.indexOf(c),-1!=c&&(e=c));for(var c=[],a=0,d=0;d<
        e;d++)if(d%4){var g=f.indexOf(b.charAt(d-1))<<2*(d%4),h=f.indexOf(b.charAt(d))>>>6-2*(d%4);c[a>>>2]|=(g|h)<<24-8*(a%4);a++}return j.create(c,a)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();

        var webserviceData = {};
        /**
         * Class encapsulating the webservices suitetalk functionality
         * @return {void}                
         */
        function init(credentials) { // this is an id found in the integration record inside the Techfino NetSuite account

            webserviceData.accountNumber = runtime.accountId;
            // determine which type of authentication to use from initialization object
            if (credentials.username){
                webserviceData.username = credentials.username;
                webserviceData.password = credentials.password;
                webserviceData.roleId = credentials.roleId;
                webserviceData.applicationId = credentials.applicationId;
                webserviceData.generatePassport = generateNLAuthPassport;
            } else if (credentials.tokenId) {
                webserviceData.tokenId = credentials.tokenId;
                webserviceData.tokenSecret = credentials.tokenSecret;
                webserviceData.consumerKey = credentials.consumerKey;
                webserviceData.consumerSecret = credentials.consumerSecret;    
                webserviceData.generatePassport = generateTokenPassport;
            } else {
                throw 'Invalid Credentials Object';
            }

            var xmlArray = [];
            xmlArray.push('<?xml version="1.0" encoding="UTF-8"?>');
            xmlArray.push('<soapenv:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.w3.org/2001/XMLSchema">');
            xmlArray.push('<soapenv:Header>');
            xmlArray.push('{AUTHENTICATION}');
            xmlArray.push('</soapenv:Header>');
            xmlArray.push('<soapenv:Body xmlns:platformMsgs="urn:messages_2016_1.platform.webservices.netsuite.com" xmlns:platformCore="urn:core_2016_1.platform.webservices.netsuite.com" xmlns:tranInvt="urn:inventory_2016_1.transactions.webservices.netsuite.com" xmlns:tranInvtTyp="urn:types.inventory_2016_1.transactions.webservices.netsuite.com" xmlns:platformCommon="urn:common_2016_1.platform.webservices.netsuite.com" xmlns:platformCommonTyp="urn:types.common_2016_1.platform.webservices.netsuite.com" xmlns:listRel="urn:relationships_2016_1.lists.webservices.netsuite.com" xmlns:listAcctTyp="urn:types.accounting_2016_1.lists.webservices.netsuite.com" xmlns:listAcct="urn:accounting_2016_1.lists.webservices.netsuite.com" xmlns:tranFin="urn:financial_2016_1.transactions.webservices.netsuite.com" xmlns:tranFinTyp="urn:types.financial_2016_1.transactions.webservices.netsuite.com">');
            xmlArray.push('{BODY}');
            xmlArray.push('</soapenv:Body>');
            xmlArray.push('</soapenv:Envelope>');

            webserviceData.envelope = xmlArray.join('');
            webserviceData.queryURL = getDataCenterUrl();
        }

        /**
         * creates an NLAuthentication header
         * @return {string} passport with proper NLAuth authentication verification
         */
        function generateNLAuthPassport() {
            var xmlArray = []
            
            xmlArray.push('<ns1:passport soapenv:mustUnderstand="0" xmlns:ns1="urn:messages_2016_1.platform.webservices.netsuite.com">');
            xmlArray.push('<ns:email xmlns:ns="urn:messages_2016_1.platform.webservices.netsuite.com">' + webserviceData.username + '</ns:email>');
            xmlArray.push('<ns:password xmlns:ns="urn:messages_2016_1.platform.webservices.netsuite.com">' + webserviceData.password + '</ns:password>');
            xmlArray.push('<ns:account xmlns:ns="urn:messages_2016_1.platform.webservices.netsuite.com">' + webserviceData.accountNumber + '</ns:account>');
            xmlArray.push('<ns:role xmlns:ns="urn:messages_2016_1.platform.webservices.netsuite.com" internalId="' + webserviceData.roleId + '"/>');
            xmlArray.push('</ns1:passport>');
            xmlArray.push('<ns1:applicationInfo soapenv:mustUnderstand="0" xmlns:ns1="urn:messages_2016_1.platform.webservices.netsuite.com">');
            xmlArray.push('<ns:applicationId xmlns:ns="urn:messages_2016_1.platform.webservices.netsuite.com">' + webserviceData.applicationId + '</ns:applicationId>');
            xmlArray.push('</ns1:applicationInfo>');

            return xmlArray.join('');
        
        }
        
        /**
         * Creates a token authentication header
         * @return {string} passport with proper token authentication verification
         */
        function generateTokenPassport() {

            if (!webserviceData.queryURL) return "";

            var timestamp = Math.round(new Date().getTime() / 1000);
            var nonce = webserviceData.generateNonce();
            var xmlArray = [];
            // create string for signature
            var baseString = escape(webserviceData.accountNumber) + '&' +
                escape(webserviceData.consumerKey) + '&' +
                escape(webserviceData.tokenId) + '&' +
                escape(nonce) + '&' +
                escape(timestamp);

            var key = escape(webserviceData.consumerSecret) + '&' +
                escape(webserviceData.tokenSecret);
            
            var signature = CryptoJS.HmacSHA1(baseString, key).toString(CryptoJS.enc.Base64);

            xmlArray.push('<ns:tokenPassport xmlns:ns="urn:messages_2016_1.platform.webservices.netsuite.com">');
            xmlArray.push('<ns:account>' + webserviceData.accountNumber + '</ns:account>');
            xmlArray.push('<ns:consumerKey>' + webserviceData.consumerKey + '</ns:consumerKey>');
            xmlArray.push('<ns:token>' + webserviceData.tokenId + '</ns:token>');
            xmlArray.push('<ns:nonce>' + nonce + '</ns:nonce>');
            xmlArray.push('<ns:timestamp>' + timestamp + '</ns:timestamp>');
            xmlArray.push('<ns:signature algorithm="HMAC_SHA1">' + signature + '=</ns:signature>');
            xmlArray.push('</ns:tokenPassport>');

            return xmlArray.join('');
        };

        /**
         * Generates random string of alphanumeric characters for use in encryption. Courtesty stack overflow
         * @return {string}              string of 20 random alphanumeric characters
         */
        function generateNonce() {
            var chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            var NONCE_LENGTH = 20; // default to 20
            var result = '';
            for (var i = NONCE_LENGTH; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
            return result;
        };

        /**
         * Specifies a search filter to add to the search call
         * @param {string} name     name of field
         * @param {[type]} type     [description]
         * @param {[type]} operator [description]
         * @param {[type]} value    [description]
         */
        function addSearchFilter(name, type, operator, value) {
            var xmlArray = [];
            xmlArray.push('<platformCommon:' + name + ' xsi:type="platformCore:' + type + '" operator="' + operator + '">');
            if (typeof value === 'object'){
                for (var i = 0; i < value.length; i++) {
                    xmlArray.push('<platformCore:searchValue xsi:type="platformCore:RecordRef" internalId="' + value[i] + '"></platformCore:searchValue>');
                }
            } else {
                xmlArray.push('<platformCore:searchValue xsi:type="platformCore:RecordRef" internalId="' + value + '"></platformCore:searchValue>');
            }
            xmlArray.push('</platformCommon:' + name + '>');
            return xmlArray.join('');
        };
        /**
         * Adds a field for initialization or updating a value on a record
         * @param {string} name  name of field
         * @param {string} value value of field
         * @param {string} type  type of field added
         */
        function addRecordField(name, value, type) {
            if (type) {
                if (type === 'RecordRef') { // adding list/record reference
                    return '<tranFin:' + name + '  xsi:type="platformCore:RecordRef" internalId="' + value + '"/>';
                } else {
                    return '<tranFin:' + name + ' xsi:type="' + type + '">' + value + '</tranFin:' + name + '>';
                }
            }
            return '<tranFin:' + name + '>' + value + '</tranFin:' + name + '>';
        };

        /**
         * performs webservices 'search' action
         * @param {string} recordType    the record internalid
         * @param {object} initialFields array of objects specifying fields and values to search
         */
        function search(recordType, filters, columns) {
            var headers = []; //declare the webservice headers

            headers['Content-Type'] = 'text/xml';
            headers['SOAPAction'] = 'search';

            var xmlArray = [];
            xmlArray.push('<search xmlns="urn:messages_2016_1.platform.webservices.netsuite.com">');
            xmlArray.push('<searchRecord xsi:type="platformCommon:' + recordType + 'SearchBasic" xmlns:platformCommon="urn:common_2016_1.platform.webservices.netsuite.com">');
            for (var i = 0; i < filters.length; i++) {
                xmlArray.push(addSearchFilter(filters[i].name, filters[i].type, filters[i].operator, filters[i].value));
            }
            xmlArray.push('</searchRecord>');
            xmlArray.push('</search>');

            var xmlBody = xmlArray.join('');

            var responseBody = sendRequestAndParseResponse(webserviceData.queryURL, xmlBody,headers)

            var results = [];
            // log.debug({ 'title': 'response', details: JSON.stringify(searchResponse) });
            var searchResults = responseBody.getElementsByTagNameNS({ namespaceURI: '*', localName: 'record' });
            var searchId = responseBody.getElementsByTagNameNS({ namespaceURI: '*', localName: 'nsId' })[0].textContent
            var totalPages = parseInt(responseBody.getElementsByTagNameNS({ namespaceURI: '*', localName: 'totalPages' })[0].textContent)

            // loop for all results. first search gives back first page
            for (var pageIndex = 2; pageIndex <= totalPages; pageIndex++) {
                searchResults = searchResults.concat(searchMoreWithId(searchId, pageIndex));
            }

            for (var searchResultIndex = 0; searchResultIndex < searchResults.length; searchResultIndex++) {
                var tempObj = results[searchResultIndex] = {};
                var searchResult = searchResults[searchResultIndex];
                tempObj['id'] = searchResult.getAttribute('internalId');
                // go through each column provided
                for (var columnIndex = 0; columnIndex < columns.length; columnIndex++) {
                    var currentColumn = columns[columnIndex].name;
                    if (!currentColumn) throw "Column not formatted properly";
                    var columnValue = searchResult.getElementsByTagNameNS({ namespaceURI: '*', localName: currentColumn })[0];
                    if (columnValue) {
                        var resultValue = columnValue.getAttribute('internalId');
                        var resultText = columnValue.textContent || '';
                        if (resultValue) {
                            results[searchResultIndex][currentColumn] = {
                                value: resultValue,
                                text: resultText
                            };
                        } else {
                            results[searchResultIndex][currentColumn] = resultText;
                        }
                    } else {
                        results[searchResultIndex][currentColumn] = '';
                    }

                }
            }

            return results;

        };

        /**
         * Get additional results for a search
         * @param  {string} searchId  Alphanumeric value denoting the search
         * @param  {number} pageIndex Which page of the results are requested
         * @return {Object}           Returns a result set in the form of an array
         */
        function searchMoreWithId(searchId, pageIndex){ 
             var headers = []; //declare the webservice headers

            headers['Content-Type'] = 'text/xml';
            headers['SOAPAction'] = 'searchMoreWithId';

            var xmlArray = [];
            xmlArray.push('<platformMsgs:searchMoreWithId>');
            xmlArray.push('<searchId>' + searchId + '</searchId>');
            xmlArray.push('<pageIndex>' + pageIndex + '</pageIndex>');
            xmlArray.push('</platformMsgs:searchMoreWithId>');

             var xmlBody = xmlArray.join('');

            var responseBody = sendRequestAndParseResponse(webserviceData.queryURL, xmlBody,headers)

            return responseBody.getElementsByTagNameNS({ namespaceURI: '*', localName: 'record' });
         }

        /**
         * performs webservices 'add' action
         * @param {string} recordType    the record internalid
         * @param {object} initialFields array of objects specifying initial fields and what to set
         */
        function add(recordType, initialFields) {
            var headers = []; //declare the webservice headers

            headers['Content-Type'] = 'text/xml';
            headers['SOAPAction'] = 'add';

            var xmlArray = [];

            xmlArray.push('<platformMsgs:add>');
            xmlArray.push('<platformMsgs:record xsi:type="tranFin:' + recordType + '">');
            for (var iFieldsNum = 0; iFieldsNum < initialFields.length; iFieldsNum++) {
                xmlArray.push(addRecordField(initialFields[iFieldsNum].name, initialFields[iFieldsNum].value, initialFields[iFieldsNum].type));
            }
            xmlArray.push('</platformMsgs:record>');
            xmlArray.push('</platformMsgs:add>');

            var xmlBody = xmlArray.join('');

            var responseBody = sendRequestAndParseResponse(webserviceData.queryURL, xmlBody,headers)
            return responseBody;
        };

        /**
         * performs webservices 'addlist' action
         * @param {string} recordType    the record internalid
         * @param {object} initialFields array of objects specifying initial fields and what to set
         */
        function addList(addList) {
            var headers = []; //declare the webservice headers

            headers['Content-Type'] = 'text/xml';
            headers['SOAPAction'] = 'addList';

            var xmlArray = [];

            xmlArray.push('<platformMsgs:addList>');
            for (var recordIndex = 0; recordIndex < addList.length; recordIndex++) {
                var recordType = addList[recordIndex].type;
                var initialFields = addList[recordIndex].initialFields;
                xmlArray.push('<platformMsgs:record xsi:type="tranFin:' + recordType + '">');
                for (var iFieldsNum = 0; iFieldsNum < initialFields.length; iFieldsNum++) {
                    xmlArray.push(addRecordField(initialFields[iFieldsNum].name, initialFields[iFieldsNum].value, initialFields[iFieldsNum].type));
                }
                xmlArray.push('</platformMsgs:record>');
            }

            xmlArray.push('</platformMsgs:addList>');

            var xmlBody = xmlArray.join('');

            var responseBody = sendRequestAndParseResponse(webserviceData.queryURL, xmlBody,headers)
            
            return responseBody;
        };

        /**
         * performs webservices 'update' action
         * @param {string} recordType    the record internalid
         * @param {object} initialFields array of objects specifying initial fields and what to set
         */
        function update(recordType, internalid, fields) {
            var headers = []; //declare the webservice headers

            headers['Content-Type'] = 'text/xml';
            headers['SOAPAction'] = 'update';

            var xmlArray = [];
            xmlArray.push('<platformMsgs:update>');
            xmlArray.push('<platformMsgs:record xsi:type="tranFin:' + recordType + '" internalId="' + internalid + '" >');
            for (var uFieldsIndex = 0; uFieldsIndex < fields.length; uFieldsIndex++) {
                xmlArray.push(addRecordField(fields[uFieldsIndex].name, fields[uFieldsIndex].value, fields[uFieldsIndex].type));
            }
            xmlArray.push('</platformMsgs:record>');
            xmlArray.push('</platformMsgs:update>');

            var xmlBody = xmlArray.join('');

            var responseBody = sendRequestAndParseResponse(webserviceData.queryURL, xmlBody,headers)
            return responseBody;
        };

        /**
         * performs webservices 'updatelist' action
         * @param {string} recordType    the record internalid
         * @param {object} initialFields array of objects specifying initial fields and what to set
         */
        function updateList(updateList) {
            var headers = []; //declare the webservice headers

            headers['Content-Type'] = 'text/xml';
            headers['SOAPAction'] = 'updateList';

            var xmlArray = [];
            xmlArray.push('<platformMsgs:updateList>');
            for (var recordIndex = 0; recordIndex < updateList.length; recordIndex++) {
                var recordType = updateList[recordIndex].type;
                var recordId = updateList[recordIndex].id;
                var fields = updateList[recordIndex].updateFields;
                xmlArray.push('<platformMsgs:record xsi:type="tranFin:' + recordType + '" internalId="' + recordId + '" >');
                for (var uFieldsIndex = 0; uFieldsIndex < fields.length; uFieldsIndex++) {
                    xmlArray.push(addRecordField(fields[uFieldsIndex].name, fields[uFieldsIndex].value, fields[uFieldsIndex].type));
                }
                xmlArray.push('</platformMsgs:record>');
            }
            xmlArray.push('</platformMsgs:updateList>');

            var xmlBody = xmlArray.join('');

            var responseBody = sendRequestAndParseResponse(webserviceData.queryURL, xmlBody,headers)
            return responseBody;
        };


        /**
         * performs webservices 'get' action
         * @param {string} recordType    the record internalid
         * @param {number} internalid    the record internalid
         * @param {object} initialFields array of objects specifying initial fields and what to set
         */
        function get(recordType, internalid) {
            var headers = []; //declare the webservice headers

            headers['Content-Type'] = 'text/xml';
            headers['SOAPAction'] = 'get';

            var xmlArray = [];

            xmlArray.push('<platformMsgs:get>');
            xmlArray.push('<platformMsgs:baseRef internalId="' + internalid + '" type="' + recordType + '" xsi:type="platformCore:RecordRef">');
            xmlArray.push('<platformCore:name/>');
            xmlArray.push('</platformMsgs:baseRef>');
            xmlArray.push('</platformMsgs:get>');

            var xmlBody = xmlArray.join('');
            var responseBody = sendRequestAndParseResponse(webserviceData.queryURL, xmlBody,headers)

            return responseBody;
        };

        /**
         * performs webservices 'get' action
         * @param {string} recordType    the record internalid
         * @param {number} internalid    the record internalid
         * @param {object} initialFields array of objects specifying initial fields and what to set
         */
        function deleteList(recordsToDelete) {
            var headers = []; //declare the webservice headers

            headers['Content-Type'] = 'text/xml';
            headers['SOAPAction'] = 'deleteList';

            var xmlArray = [];

            xmlArray.push('<platformMsgs:deleteList >');
            for (var dRecordIndex = 0; dRecordIndex < recordsToDelete.length; dRecordIndex++) {
                xmlArray.push('<platformMsgs:baseRef internalId="' + recordsToDelete[dRecordIndex].id + '" type="' + recordsToDelete[dRecordIndex].type + '" xsi:type="platformCore:RecordRef"/>');
            }
            xmlArray.push('</platformMsgs:deleteList>');

            var xmlBody = xmlArray.join('');
            var responseBody = sendRequestAndParseResponse(webserviceData.queryURL, xmlBody,headers)

            return responseBody;
        };

        /**
         * Adds webservice call header and envelope to body call
         * @param  {string} body xml string of webservices body call
         * @return {string}      xml string of full webservices call
         */
        function generateRequest(body) {
            var request = webserviceData.envelope.replace('{AUTHENTICATION}', webserviceData.generatePassport()).replace('{BODY}', body);
            // log.debug({ 'title': 'request', details: request });
            return request;
        };

        /**
         * Sends request with redundancy / retries
         * @param  {string} xmlPayload The xml payload 
         * @param  {object} headers    The headers for the request
         * @return {[type]}            [description]
         */
        function sendRequestAndParseResponse(url,xmlBody,headers){
            var MAX_ATTEMPTS = 10; // This should be way more than enough to ensure temporary issues 
            var retryAttempt = 0;
            while(retryAttempt < MAX_ATTEMPTS){   
                try {
                    var xmlPayload = generateRequest(xmlBody);
                    var searchResponse = https.post({ url: url, body: xmlPayload, headers: headers }); // creates and calls the web service response
                    var responseBody = xml.Parser.fromString({ text: searchResponse.body }); // gets the body of the request into XML form
                    var responseCode = parseInt(searchResponse.code);
                    var responseStatus = responseBody.getElementsByTagNameNS({ namespaceURI: '*', localName: 'status' });
                    // NetSuite Returned errors
                    if (responseCode !== 200) {
                        // syntax or request error
                        var faultString = responseBody.getElementsByTagNameNS({ namespaceURI: '*', localName: 'faultstring' })[0].textContent;
                        log.error({ 'title': 'WEBSERVICES_RESPONSE_ERROR', 'details': faultString });
                    } else if (responseStatus.length > 0 && responseStatus[0].getAttribute('isSuccess') === "false") {
                        // NetSuite returned error 
                        var faultCode = responseBody.getElementsByTagNameNS({ namespaceURI: '*', localName: 'code' })[0].textContent;
                        var faultMessage = responseBody.getElementsByTagNameNS({ namespaceURI: '*', localName: 'message' })[0].textContent;
                        log.error({ 'title': 'WEBSERVICES_RESPONSE_ERROR', 'details': faultCode + ': ' + faultMessage });
                    } else { // passes all checks
                        // log.debug({ 'title': 'response', details: JSON.stringify(response) });
                        return responseBody;
                    }
                } catch(errorMessage){ // error from sending request
                    log.error({ 'title': 'WEBSERVICES_REQUEST_ERROR', 'details': errorMessage.toString() });
                }

                retryAttempt++;
            }
            
            log.error({ 'title': 'FAILED REQUEST XML', 'details': JSON.stringify(xmlPayload) });
            log.error({ 'title': 'FAILED REQUEST HEADERS', 'details': JSON.stringify(headers) });
            throw error.create({ name: 'UNRECOVERABLE_WEBSERVICE_ERROR', message: 'UNABLE TO RECOVER WITH RETRIES' });
        
        };

        /**
         * Dynamic call to NetSuite for initial URL to call for webservices
         * @return {void} sets class query url
         */
        function getDataCenterUrl() {

            var headers = []; //declare the webservice headers
            headers['Content-Type'] = 'text/xml';
            headers['SOAPAction'] = 'getDataCenterUrls';

            var xmlArray = [];

            xmlArray.push('<getDataCenterUrls>');
            xmlArray.push('<account>' + webserviceData.accountNumber + '</account>');
            xmlArray.push('</getDataCenterUrls>');

            var xmlBody = xmlArray.join('');

            var sUrl = "https://webservices.netsuite.com/services/NetSuitePort_2016_1";
            if (runtime.envType === 'SANDBOX') {
                sUrl = sUrl.replace('.netsuite', '.sandbox.netsuite');
            }

            var dataCentersBody = sendRequestAndParseResponse(sUrl, xmlBody,headers)

            var webServicesNode = dataCentersBody.getElementsByTagNameNS({ namespaceURI: '*', localName: "webservicesDomain" }); // gets the webservices domain no}de
            var webServicesURL = webServicesNode[0].textContent; // get the text content of the node and store it to a variable to use
            var wsdlVersion = '/services/NetSuitePort_2016_1';
            var finalURL = webServicesURL + wsdlVersion;
            // if (runtime.envType === 'SANDBOX') {
            //     finalURL = finalURL.replace('.netsuite', '.sandbox.netsuite');
            // }
            return finalURL

        };

        return {
            add: add,
            addList: addList,
            deleteList: deleteList,
            get: get,
            init: init,
            search: search,
            update: update,
            updateList: updateList,
        };
    });