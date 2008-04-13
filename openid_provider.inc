<?php
// $Id$

/**
 * Create an association with an RP
 *
 * @param array $request
 */
function openid_provider_association_response($request) {
  module_load_include('inc', 'openid');
  
  $session_type = $request['openid.session_type'];
  $assoc_type = $request['openid.assoc_type'];
  $dh_modulus = $request['openid.dh_modulus'];
  $dh_gen = $request['openid.dh_gen'];
  $dh_consumer_public = $request['openid.dh_consumer_public'];

  $assoc_handle = _openid_provider_nonce();
  $expires_in = variable_get('openid_provider_assoc_expires_in', '3600');

  // CLEAR STALE ASSOCIATIONS
  db_query("DELETE FROM {openid_provider_association} WHERE created + expires_in < %d", time());
  
  $response = array(
    'ns' => OPENID_NS_2_0,
    'session_type' => $session_type,
    'assoc_handle' => $assoc_handle,
    'assoc_type' => $assoc_type,
    'expires_in' => $expires_in
  );

  $secret = _openid_get_bytes(20);
  if ($session_type == '' || $session_type == 'no-encryption') {
    if ($assoc_type == 'HMAC-SHA1') {
      $mac_key = _openid_hmac($secret, $response['assoc_handle']);
      $response['mac_key'] = $mac_key;
    }
    elseif ($assoc_type == 'HMAC-SHA256') {
      // TODO: Not yet supported
    }
  }
  elseif ($session_type == 'DH-SHA1' || $session_type == 'DH-SHA256') {
    $dh_assoc = openid_provider_dh_assoc($request, $secret);
    $mac_key = base64_encode($secret);
    $response['dh_server_public'] = $dh_assoc['dh_server_public'];
    $response['enc_mac_key'] = $dh_assoc['enc_mac_key'];
  }

  // Save the association for reference when dealing
  // with future requests from the same RP.
  db_query("INSERT INTO {openid_provider_association} (assoc_handle, assoc_type, session_type, mac_key, created, expires_in) VALUES ('%s', '%s', '%s', '%s', %d, %d)",
           $assoc_handle, $assoc_type, $session_type, $mac_key, time(), $expires_in);

  
  if ($assoc_type == 'HMAC-SHA256' || $session_type == 'DH-SHA256') {
    $message = _openid_create_message(openid_provider_association_error());
  }
  else {
    $message = _openid_create_message($response);
  }

  drupal_set_header('HTTP/1.1 200 OK');
  drupal_set_header("Content-Type: text/plain");
  print $message;
}

/**
 * Generate an association error response
 */
function openid_provider_association_error() {
  return array(
    'error' => '', // optional
    'error_code' => 'unsupported-type',
    'session_type' => '', // optional
    'assoc_type' => '' // optional
  );
}

/**
 * Generate an authentication response
 *
 * @param 
 */
function openid_provider_authentication_response($request) {
  global $user;

  // If the user is not yet logged in, redirect to the login page before continuing.
  if (!$user->uid) {
    $_SESSION['openid_provider']['request'] = $request;
    drupal_goto('user/login', 'destination=openid/provider/continue');
  }

  // Determine the realm (openid.trust_root in 1.x)
  $realm = (empty($request['openid.realm'])) ? $request['openid.trust_root'] : $request['openid.realm'];

  // Check for a directed identity request.
  if ($request['openid.identity'] == 'http://specs.openid.net/auth/2.0/identifier_select') {
    $identity = url('user/' . $user->uid, array('absolute' => TRUE));
  }
  else {
    $identity = $request['openid.identity'];
    if ($identity != url('user/'. $user->uid, array('absolute' => TRUE))) {
      $response = openid_provider_authentication_error($request['openid.mode']);
      openid_redirect($request['openid.return_to'], $response);
    }
  }

  $response = array(
    'openid.ns' => OPENID_NS_2_0,
    'openid.mode' => 'id_res',
    'openid.op_endpoint' => url('openid/provider', array('absolute' => TRUE)),
    'openid.identity' => $identity,
    'openid.claimed_id' => $identity,
    'openid.return_to' => $request['openid.return_to'],
    'openid.response_nonce' => _openid_provider_nonce(),
    'openid.assoc_handle' => $request['openid.assoc_handle']
  );

  // Is the RP requesting Immediate or Indirect mode?
  if ($request['openid.mode'] == 'checkid_immediate') {
    // TODO
  }
  
  $parts = parse_url($request['openid.return_to']);
  if (isset($parts['query'])) {
    $query = $parts['query'];
    $q = _openid_get_params($query);
    foreach ($q as $key => $val) {
      $response[$key] = $val;
    }
  }
  
  $rp = _openid_provider_rp_load($user->uid, $realm);
  if ($rp->auto_release) {
    $response = _openid_provider_sign($response);
    _openid_provider_rp_save($user->uid, $realm, TRUE);
    return openid_redirect_http($response['openid.return_to'], $response); 
  }
  else {
    return drupal_get_form('openid_provider_form', $response, $realm);
  }
}

/**
 * Negative assertion
 */
function openid_provider_authentication_error($mode) {
  if ($mode == 'checkid_immediate') {
    return array(
      'openid.mode' => 'id_res',
      'openid.user_setup_url' => url('user/login', NULL, NULL, TRUE)
    );
  }
  else { // checkid_setup
    return array(
      'openid.mode' => 'cancel'
    );
  }
}



function openid_provider_dh_assoc($request, $secret) {
  if (empty($request['openid.dh_consumer_public'])) {
    return FALSE;
  }
  
  if (isset($request['openid.dh_modulus'])) {
    $mod = _openid_dh_base64_to_long($request['openid.dh_modulus']);
  }
  else {
    $mod = OPENID_DH_DEFAULT_MOD;
  }

  if (isset($request['openid.dh_gen'])) {
    $gen = _openid_dh_base64_to_long($request['openid.dh_gen']);
  }
  else {
    $gen = OPENID_DH_DEFAULT_GEN;
  }

  $r = _openid_dh_rand($mod);
  $private = bcadd($r, 1);
  $public = bcpowmod($gen, $private, $mod);
  
  $cpub = _openid_dh_base64_to_long($request['openid.dh_consumer_public']);
  $shared = bcpowmod($cpub, $private, $mod);
  $mac_key = _openid_dh_xorsecret($shared, $secret);
  $enc_mac_key = base64_encode($mac_key);
  $spub64 = _openid_dh_long_to_base64($public);
  return array(
    'dh_server_public' => $spub64,
    'enc_mac_key' => $enc_mac_key
    );
}

// 9.2.2.2. Verifying Directly with the Identity Provider
// 9.2.2.2.2. Response Parameters
// Request is: Exact copies of all fields from the authentication response
function openid_provider_verification_response($request) {
  $is_valid = TRUE;
  
  // Use the request openid.assoc_handle to look up
  // how this message should be signed, based on
  // a previously-created association.
  $assoc_type = 'HMAC-SHA1';
  $assoc = db_fetch_object(db_query("SELECT * FROM {openid_provider_association} WHERE assoc_handle = '%s'", 
    $request['openid.assoc_handle']));
  if ($assoc && $assoc->assoc_type != '') {
    $assoc_type = $assoc->assoc_type;
  }

  $signed_keys = explode(',', $request['openid.signed']);
  $signature = _openid_signature($assoc, $request, $signed_keys);

  if ($signature != $request['openid.sig']) {
    $is_valid = FALSE;
  }

  if ($is_valid) {
    $response = array('is_valid' => 'true');
  }
  else {
    $response = array(
      'is_valid' => 'false',
      'invalidate_handle' => $request['openid.assoc_handle'] // optional, An association handle sent in the request
    );
  }

  $message = _openid_create_message($response);
  header("Content-Type: text/plain");
  print $message;  
}

function openid_provider_cancel_authentication_response($mode = 'checkid_immediate') {
  $response = array();
  if ($mode == 'checkid_immediate') {
    $response = array(
      'openid.ns' => OPENID_NS_2_0,
      'openid.mode' => 'id_res',
      'openid.user_setup_url' => url('user', NULL, NULL, TRUE)
    );
  }
  else {
    $response = array('openid.module' => OPENID_NS_2_0, 'openid.mode' => 'cancel');
  }
  return $response;
}

function _openid_provider_rp_load($uid, $realm = NULL) {
  if ($realm) {
    return db_fetch_object(db_query("SELECT * FROM {openid_provider_relying_party} WHERE uid=%d AND realm='%s'", $uid, $realm));
  }
  else {
    $rps = array();
    $result = db_query("SELECT * FROM {openid_provider_relying_party} WHERE uid=%d ORDER BY last_time DESC", $uid);
    while ($rp = db_fetch_object($result)){
      $rps[] = $rp;
    }
    return $rps;
  }
}
  
function _openid_provider_rp_save($uid, $realm, $auto_release = FALSE) {
  $rpid = db_result(db_query("SELECT rpid FROM {openid_provider_relying_party} WHERE uid=%d AND realm='%s'", $uid, $realm));
  if ($rpid) {
    db_query("UPDATE {openid_provider_relying_party} SET auto_release=%d, last_time=%d WHERE rpid=%d", $auto_release, time(), $rpid);  
  }
  else {
    db_query("INSERT INTO {openid_provider_relying_party} (uid, realm, first_time, last_time, auto_release) VALUES (%d, '%s', %d, %d, %d)", $uid, $realm, time(), time(), $auto_release);
  }
}
function _openid_provider_nonce() {
  // YYYY-MM-DDThh:mm:ssTZD UTC, plus some optional extra unique chars
  return gmstrftime('%Y-%m-%dT%H:%M:%SZ') .
    chr(mt_rand(0, 25) + 65) .
    chr(mt_rand(0, 25) + 65) .
    chr(mt_rand(0, 25) + 65) .
    chr(mt_rand(0, 25) + 65);
}

function _openid_provider_sign($response) {
  module_load_include('inc', 'openid');
  
  $also_sign = array();
  $parts = parse_url($response['openid.return_to']);
  if (isset($parts['query'])) {
    $query = $parts['query'];
    $q = _openid_get_params($query);
    foreach ($q as $key => $val) {
      $also_sign[] = $key;
      $response[$key] = $val;
    }
  }

  $signed_keys = array('op_endpoint', 'return_to', 'response_nonce', 'assoc_handle', 'identity', 'claimed_id');
  $signed_keys = array_merge($signed_keys, module_invoke_all('openid', 'signed', $response));
//  $signed_keys = array_merge($signed_keys, $also_sign);
  $response['openid.signed'] = implode(',', $signed_keys);
  
  // Use the request openid.assoc_handle to look up
  // how this message should be signed, based on
  // a previously-created association.
  $assoc = db_fetch_object(db_query("SELECT * FROM {openid_provider_association} WHERE assoc_handle = '%s'", 
                                    $response['openid.assoc_handle']));
  
  // Generate signature for this message
  $response['openid.sig'] = _openid_signature($assoc, $response, $signed_keys);
  return $response;
}
