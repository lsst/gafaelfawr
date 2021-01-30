import PropTypes from 'prop-types';
import React, {
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import { LoginContext } from './loginContext';
import Timestamp from './timestamp';
import Token from './token';
import TokenName from './tokenName';
import { apiGet } from '../functions/api';

export default function TokenData({ token, onError }) {
  const { username } = useContext(LoginContext);
  const [_tokenData, setTokenData] = useState(null);
  const tokenData = useMemo(() => _tokenData, [_tokenData]);

  const loadTokenData = useCallback(() => {
    if (!username) return;
    apiGet(`/users/${username}/tokens/${token}`)
      .then(setTokenData)
      .catch(onError);
  }, [onError, token, username]);

  useEffect(loadTokenData, [loadTokenData, token, username]);

  if (!tokenData) return <p>Loading...</p>;

  return (
    <table>
      <tbody>
        <tr>
          <th scope="row">Token</th>
          <td>
            <Token token={tokenData.token} link={false} />
          </td>
        </tr>
        <tr>
          <th scope="row">Username</th>
          <td>{tokenData.username}</td>
        </tr>
        <tr>
          <th scope="row">Type</th>
          <td>{tokenData.token_type}</td>
        </tr>
        {tokenData.token_name && (
          <tr>
            <th scope="row">Name</th>
            <td>
              <TokenName name={tokenData.token_name} />
            </td>
          </tr>
        )}
        <tr>
          <th scope="row">Scopes</th>
          <td>{tokenData.scopes.join(', ')}</td>
        </tr>
        {tokenData.service && (
          <tr>
            <th scope="row">Service</th>
            <td>{tokenData.service}</td>
          </tr>
        )}
        {tokenData.parent && (
          <tr>
            <th scope="row">Parent</th>
            <td>
              <Token token={tokenData.parent} />
            </td>
          </tr>
        )}
        <tr>
          <th scope="row">Created</th>
          <td>
            <Timestamp timestamp={tokenData.created} past />
          </td>
        </tr>
        <tr>
          <th scope="row">Last Used</th>
          <td>
            <Timestamp timestamp={tokenData.last_used} past />
          </td>
        </tr>
        <tr>
          <th scope="row">Expires</th>
          <td>
            <Timestamp timestamp={tokenData.expires} past={false} />
          </td>
        </tr>
      </tbody>
    </table>
  );
}
TokenData.propTypes = {
  token: PropTypes.string.isRequired,
  onError: PropTypes.func.isRequired,
};
