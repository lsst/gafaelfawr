import PropTypes from 'prop-types';
import React, {
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { useTable } from 'react-table';

import { LoginContext } from './loginContext';
import Timestamp from './timestamp';
import { apiGet } from '../functions/api';

export default function TokenChangeHistory({ token, onError }) {
  const { username } = useContext(LoginContext);
  const [_data, setData] = useState([]);
  const data = useMemo(() => _data, [_data]);

  const columns = useMemo(
    () => [
      {
        Header: 'Event Time',
        // eslint-disable-next-line react/display-name, react/prop-types
        Cell: ({ value }) => <Timestamp timestamp={value} past />,
        accessor: 'event_time',
      },
      {
        Header: 'Action',
        accessor: 'action',
      },
      {
        Header: 'Actor',
        accessor: 'actor',
      },
      {
        Header: 'IP Address',
        accessor: 'ip_address',
      },
      {
        Header: 'Token Name',
        accessor: 'token_name',
      },
      {
        Header: 'Old Token Name',
        accessor: 'old_token_name',
      },
      {
        Header: 'Scopes',
        // eslint-disable-next-line react/prop-types
        Cell: ({ value }) => (value ? value.join(', ') : null),
        accessor: 'scopes',
      },
      {
        Header: 'Old Scopes',
        // eslint-disable-next-line react/prop-types
        Cell: ({ value }) => (value ? value.join(', ') : null),
        accessor: 'old_scopes',
      },
      {
        Header: 'Expires',
        // eslint-disable-next-line react/display-name, react/prop-types
        Cell: ({ value }) => <Timestamp timestamp={value} past={false} />,
        accessor: 'expires',
      },
      {
        Header: 'Old Expires',
        // eslint-disable-next-line react/display-name, react/prop-types
        Cell: ({ value }) => <Timestamp timestamp={value} past={false} />,
        accessor: 'old_expires',
      },
    ],
    []
  );

  const loadHistory = useCallback(() => {
    if (!username) return;
    apiGet(`/users/${username}/tokens/${token}/change-history`)
      .then(setData)
      .catch(onError);
  }, [onError, token, username]);

  useEffect(loadHistory, [loadHistory, token, username]);

  const table = useTable({ columns, data });

  const {
    getTableProps,
    getTableBodyProps,
    headerGroups,
    rows,
    prepareRow,
  } = table;

  if (!data.length) return <p>Loading...</p>;

  /* eslint-disable react/jsx-props-no-spreading */
  return (
    <table {...getTableProps()}>
      <thead>
        {headerGroups.map((headerGroup) => (
          <tr {...headerGroup.getHeaderGroupProps()}>
            {headerGroup.headers.map((column) => (
              <th {...column.getHeaderProps()}>{column.render('Header')}</th>
            ))}
          </tr>
        ))}
      </thead>
      <tbody {...getTableBodyProps()}>
        {rows.map((row) => {
          prepareRow(row);
          return (
            <tr {...row.getRowProps()} className="qa-token-change-row">
              {row.cells.map((cell) => (
                <td {...cell.getCellProps()}>{cell.render('Cell')}</td>
              ))}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
  /* eslint-enable react/jsx-props-no-spreading */
}
TokenChangeHistory.propTypes = {
  token: PropTypes.string.isRequired,
  onError: PropTypes.func.isRequired,
};
