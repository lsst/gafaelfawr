import PropTypes from 'prop-types';
import React, {
  useCallback,
  useContext,
  useState,
  useEffect,
  useMemo,
} from 'react';

import CreateTokenButton from './createTokenButton';
import EditTokenModal from './editTokenModal';
import { LoginContext } from './loginContext.js';
import TokenTable from './tokenTable';
import useError from '../hooks/error';
import { apiDelete, apiGet, apiPost } from '../functions/api';

export default function TokenList({ onError }) {
  const { csrf, username, userScopes, config } = useContext(LoginContext);
  const [data, setData] = useState(null);
  const [editingToken, _setEditingToken] = useState(null);
  const tokens = useMemo(() => data, [data]);
  const { error: createError, onError: onCreateError } = useError();

  const setEditingToken = useCallback((token) => _setEditingToken(token), [
    _setEditingToken,
  ]);
  const clearEditingToken = useCallback(() => _setEditingToken(null), [
    _setEditingToken,
  ]);

  const loadTokenData = useCallback(() => {
    if (!username) return;
    apiGet(`/users/${username}/tokens`)
      .then((tokenList) => ({
        user: tokenList.filter((t) => t.token_type === 'user'),
        session: tokenList.filter((t) => t.token_type === 'session'),
        notebook: tokenList.filter((t) => t.token_type === 'notebook'),
        internal: tokenList.filter((t) => t.token_type === 'internal'),
      }))
      .then(setData)
      .catch(onError);
  }, [onError, username]);

  const createToken = useCallback(
    async ({ name, scopes, expires }, setNewToken) => {
      await apiPost(`/users/${username}/tokens`, csrf, {
        token_name: name,
        scopes,
        expires,
      })
        .then((response) => setNewToken(response.token))
        .then(loadTokenData)
        .catch(onCreateError);
    },
    [csrf, loadTokenData, onCreateError, username]
  );

  const editToken = useCallback(() => {
    clearEditingToken();
    loadTokenData();
  }, [clearEditingToken, loadTokenData]);

  const deleteToken = useCallback(
    async (token) => {
      await apiDelete(`/users/${username}/tokens/${token}`, csrf)
        .then(loadTokenData)
        .catch(onError);
    },
    [csrf, loadTokenData, onError, username]
  );

  useEffect(loadTokenData, [loadTokenData, username]);

  if (!data) return <p>Loading...</p>;

  return (
    <>
      <h2>User Tokens</h2>
      <CreateTokenButton
        error={createError}
        userScopes={userScopes}
        knownScopes={config.scopes}
        onCreateToken={createToken}
      />
      {tokens.user.length ? (
        <TokenTable
          id="tokens-user"
          data={tokens.user}
          includeName
          onDeleteToken={deleteToken}
          onEditToken={setEditingToken}
        />
      ) : null}
      <h2>Web Sessions</h2>
      <TokenTable
        id="tokens-session"
        data={tokens.session}
        onDeleteToken={deleteToken}
      />
      {tokens.notebook.length ? (
        <>
          <h2>Notebook Tokens</h2>
          <TokenTable
            id="tokens-notebook"
            data={tokens.notebook}
            onDeleteToken={deleteToken}
          />
        </>
      ) : null}
      {tokens.internal.length ? (
        <>
          <h2>Internal Tokens</h2>
          <TokenTable
            id="tokens-internal"
            data={tokens.internal}
            onDeleteToken={deleteToken}
          />
        </>
      ) : null}
      {editingToken !== null ? (
        <EditTokenModal
          token={editingToken}
          onLoadError={onError}
          onSuccess={editToken}
          onExit={clearEditingToken}
        />
      ) : null}
    </>
  );
}
TokenList.propTypes = {
  onError: PropTypes.func.isRequired,
};
