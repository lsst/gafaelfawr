import PropTypes from 'prop-types';
import React from 'react';

export default function TokenName({ name }) {
  return <span className="qa-token-name">{name}</span>;
}
TokenName.propTypes = {
  name: PropTypes.string.isRequired,
};
