import React from 'react';

import ErrorBanner from '../components/errorBanner';
import { LoginContext } from '../components/loginContext';
import TokenInfo from '../components/tokenInfo';
import useError from '../hooks/error';
import useLogin from '../hooks/login';

export default function Home() {
  const { error, onError } = useError();
  const { csrf, username, userScopes, config } = useLogin(onError);

  return (
    <LoginContext.Provider value={{ csrf, username, userScopes, config }}>
      <div id="application">
        <ErrorBanner error={error} />
        <h1>Tokens</h1>
        <TokenInfo onError={onError} />
      </div>
    </LoginContext.Provider>
  );
}
