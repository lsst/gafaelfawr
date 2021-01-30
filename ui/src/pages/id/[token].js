import PropTypes from 'prop-types';
import React from 'react';
import ErrorBanner from '../../components/errorBanner';
import { LoginContext } from '../../components/loginContext';
import TokenData from '../../components/tokenData';
import useError from '../../hooks/error';
import useLogin from '../../hooks/login';

export default function TokenPage({ params }) {
  const { error, onError } = useError();
  const { csrf, username, userScopes, config } = useLogin(onError);

  return (
    <LoginContext.Provider value={{ csrf, username, userScopes, config }}>
      <div id="application">
        <ErrorBanner error={error} />
        <TokenData token={params.token} onError={onError} />
      </div>
    </LoginContext.Provider>
  );
}
TokenPage.propTypes = {
  params: PropTypes.shape({
    token: PropTypes.string.isRequired,
  }),
};
