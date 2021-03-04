var cognitoUserPoolId;
var cognitoUserPoolClientId;
var cognitoUserPoolObject;

var cognitoIdentityPoolId;
var region;
var unauthApiClient;
var authLoggenInCognitoUser;

$(function () {
  cognitoUserPoolId = $("#txtCognitoUserPoolId").val();
  cognitoUserPoolClientId = $("#txtCognitoUserPoolClientId").val();
  cognitoIdentityPoolId = $("#txtCognitoIdentityPoolId").val();
  region = $("#txtRegion").val();
  AWS.config.region = region;

  cognitoUserPoolObject = initCognitoUserPoolObject(cognitoUserPoolId, cognitoUserPoolClientId);

  showLogIn(true);
  showLoggedIn(false);
  showRegister(false);
  showVerifyEmail(false);

  getCurrentLoggedInSession(cognitoUserPoolObject);
  loginAsUnauthUser();

  $("#btnLogin").on("click", function () {
    var username = $("#txtUsername").val();
    var password = $("#txtPassword").val();
    loginAsAuthUser(username, password, cognitoUserPoolObject);
  });

  $("#btnRegister").on("click", function () {
    showLogIn(false);
    showLoggedIn(false);
    showRegister(true);
    showVerifyEmail(false);
  });

  $("#btnLogout").on("click", function () {
    logOut();
  });

  $("#btnRegisterSubmit").on("click", function () {
    var username = $("#txtRegisterUsername").val();
    var email = $("#txtRegisterEmail").val();
    var password = $("#txtRegisterPassword").val();
    var confirmPassword = $("#txtRegisterConfirmPassword").val();
    registerUser(username, email, password);
  });

  $("#btnRegisterBack").on("click", function () {
    showLogIn(true);
    showLoggedIn(false);
    showRegister(false);
    showVerifyEmail(false);
  });

  $("#btnSubmitVerificationCode").on("click", function () {
    var verificationCode = $("#txtVerificationCode").val();
    verifyEmail(verificationCode);
  });

  $("#btnGetAnimals").on("click", function () {
    getAnimals();
  });

  $("#btnGetAnimals").on("click", function () {
    getAnimals();
  });

  $("#btnGetBrands").on("click", function () {
    getBrands();
  });

  $("#btnGetCryptocurrencies").on("click", function () {
    getCryptocurrencies();
  });

  $("#btnClearResult").on("click", function () {
    updateResultTextArea("");
  });

});

function loginAsUnauthUser() {
  var cognitoIdentity = new AWS.CognitoIdentity();

  var getIdParams = {
    IdentityPoolId: cognitoIdentityPoolId
  };
  cognitoIdentity.getId(getIdParams, function (error, data) {
    if (error) {
      console.log(error, error.stack);
    }
    else {
      console.log(data);

      var getCredentialsForIdentityParams = {
        IdentityId: data.IdentityId
      };
      cognitoIdentity.getCredentialsForIdentity(getCredentialsForIdentityParams, function (error, data) {
        if (error) {
          console.log(error, error.stack);
        }
        else {
          console.log(data);
          unauthApiClient = apigClientFactory.newClient({
            accessKey: data.Credentials.AccessKeyId,
            secretKey: data.Credentials.SecretKey,
            sessionToken: data.Credentials.SessionToken,
            region: AWS.config.region
          });

          $("#txtUnauthAwsAccessKeyId").val(data.Credentials.AccessKeyId);
          $("#txtUnauthAwsSecretKey").val(data.Credentials.SecretKey);
          $("#txtUnauthAwsSessionToken").val(data.Credentials.SessionToken);
        }
      });
    }
  });
}

function initCognitoUserPoolObject(cognitoUserPoolId, cognitoUserPoolClientId) {
  var poolData = {
    UserPoolId: cognitoUserPoolId,
    ClientId: cognitoUserPoolClientId
  };
  return new AmazonCognitoIdentity.CognitoUserPool(poolData);
}

function loginAsAuthUser(username, password, cognitoUserPoolObject) {
  var authenticationData = {
    Username: username,
    Password: password,
  };
  var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);

  var userData = {
    Username: username,
    Pool: cognitoUserPoolObject
  };
  authLoggenInCognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
  authLoggenInCognitoUser.authenticateUser(authenticationDetails, {
    onSuccess: function (result) {
      updateResultTextArea("success to login");
      getCognitoIdentityCredentials(result.getIdToken().getJwtToken());

      $("#txtLoggedInAsUsername").val(result.accessToken.payload.username);
      $("#txtLoggedInAsEmail").val(result.getIdToken().payload.email);

      showLogIn(false);
      showLoggedIn(true);
      showRegister(false);
      showVerifyEmail(false);
    },
    onFailure: function (error) {
      updateResultTextArea(error.message);
    },
  });
}

function getCurrentLoggedInSession(cognitoUserPoolObject) {
  authLoggenInCognitoUser = cognitoUserPoolObject.getCurrentUser();

  if (authLoggenInCognitoUser != null) {
    authLoggenInCognitoUser.getSession(function (error, session) {
      if (error) {
        updateResultTextArea(error.message);
      } else {
        updateResultTextArea('found logged in session');
        getCognitoIdentityCredentials(session.getIdToken().getJwtToken());

        $("#txtLoggedInAsUsername").val(session.accessToken.payload.username);
        $("#txtLoggedInAsEmail").val(session.getIdToken().payload.email);

        showLogIn(false);
        showLoggedIn(true);
        showRegister(false);
        showVerifyEmail(false);
      }
    });
  }
}

function logOut() {
  if (authLoggenInCognitoUser != null) {
    authLoggenInCognitoUser.signOut();
    AWS.config.credentials = null;
    updateResultTextArea("success to logout");
    showLogIn(true);
    showLoggedIn(false);
    showRegister(false);
    showVerifyEmail(false);

    $("#txtAuthAwsAccessKeyId").val("");
    $("#txtAuthAwsSecretKey").val("");
    $("#txtAuthAwsSessionToken").val("");
  }
}

function registerUser(username, email, password) {
  var attributeList = [];

  var dataEmail = {
    Name: 'email',
    Value: email
  };
  var attributeEmail = new AmazonCognitoIdentity.CognitoUserAttribute(dataEmail);
  attributeList.push(attributeEmail);

  cognitoUserPoolObject.signUp(username, password, attributeList, null, function (error, result) {
    if (error) {
      updateResultTextArea(error.message);
    } else {
      authLoggenInCognitoUser = result.user;

      showLogIn(false);
      showLoggedIn(false);
      showRegister(false);
      showVerifyEmail(true);
    }
  });
}

function verifyEmail(verificationCode) {
  authLoggenInCognitoUser.confirmRegistration(verificationCode, true, function (error, result) {
    if (error) {
      updateResultTextArea(error.message);
    } else {
      updateResultTextArea('success to verify code');

      showLogIn(true);
      showLoggedIn(false);
      showRegister(false);
      showVerifyEmail(false);
    }
  });
}

function showLogIn(show) {
  if (show) {
    $("#divLogin").show();
  } else {
    $("#divLogin").hide();
  }
}

function showLoggedIn(show) {
  if (show) {
    $("#divLoggedIn").show();
  } else {
    $("#divLoggedIn").hide();
  }
}

function showRegister(show) {
  if (show) {
    $("#divRegister").show();
  } else {
    $("#divRegister").hide();
  }
}

function showVerifyEmail(show) {
  if (show) {
    $("#divVerifyEmail").show();
  } else {
    $("#divVerifyEmail").hide();
  }
}

function getCognitoIdentityCredentials(idToken) {
  var loginMap = {};
  loginMap["cognito-idp." + region + ".amazonaws.com/" + cognitoUserPoolId] = idToken;

  AWS.config.credentials = new AWS.CognitoIdentityCredentials({
    IdentityPoolId: cognitoIdentityPoolId,
    Logins: loginMap
  });

  AWS.config.credentials.clearCachedId();

  AWS.config.credentials.get(function (error) {
    if (error) {
      updateResultTextArea(error.message);
    }
    else {
      $("#txtAuthAwsAccessKeyId").val(AWS.config.credentials.accessKeyId);
      $("#txtAuthAwsSecretKey").val(AWS.config.credentials.secretAccessKey);
      $("#txtAuthAwsSessionToken").val(AWS.config.credentials.sessionToken);
    }
  });
}

function getAuthUserApiClient() {
  if (AWS.config.credentials == null) {
    return null;
  }
  var apigClient = apigClientFactory.newClient({
    accessKey: AWS.config.credentials.accessKeyId,
    secretKey: AWS.config.credentials.secretAccessKey,
    sessionToken: AWS.config.credentials.sessionToken,
    region: AWS.config.region
  });

  return apigClient;
}

function getAnimals() {
  var authUserApiClient = getAuthUserApiClient();
  var apigClient = authUserApiClient != null ? authUserApiClient : unauthApiClient;

  var params = {
    foo: "foo"
  };

  apigClient.animalsGet(params).then(function (result) {
    updateResultTextArea(result.data);
  }).catch(function (error) {
    console.log(error);
    updateResultTextArea("failed to get animals!");
  });
}

function getBrands() {
  var authUserApiClient = getAuthUserApiClient();
  var apigClient = authUserApiClient != null ? authUserApiClient : unauthApiClient;

  var params = {
    foo: "foo"
  };

  apigClient.brandsGet(params).then(function (result) {
    updateResultTextArea(result.data);
  }).catch(function (error) {
    console.log(error);
    updateResultTextArea("failed to get brands!");
  });
}

function getCryptocurrencies() {
  var authUserApiClient = getAuthUserApiClient();
  var apigClient = authUserApiClient != null ? authUserApiClient : unauthApiClient;

  var params = {
    foo: "foo"
  };

  apigClient.cryptocurrenciesGet(params).then(function (result) {
    updateResultTextArea(result.data);
  }).catch(function (error) {
    console.log(error);
    updateResultTextArea("failed to get cryptocurrencies!");
  });
}

function updateResultTextArea(data) {
  $("#txtResult").val(data);
}