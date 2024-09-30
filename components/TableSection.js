// components/TableSection.js
import { Table, TableHeader, TableColumn, TableBody, TableRow, TableCell } from "@nextui-org/table";
import { Progress } from "@nextui-org/progress";
import { useMemo } from 'react';

const TableSection = ({ records, filterValue }) => {
  const columns = [
    { name: "TYPE", uid: "type" },
    { name: "VALUE", uid: "value" },
    { name: "TTL", uid: "ttl" },
    { name: "TTL EXPIRY", uid: "ttlExpiry" },
  ];

  const filteredRecords = useMemo(() => {
    return records.filter(record => 
      record.type.toLowerCase().includes(filterValue.toLowerCase()) ||
      record.value.toLowerCase().includes(filterValue.toLowerCase()) ||
      record.ttl.toString().includes(filterValue)
    );
  }, [records, filterValue]);

  return (
    <Table aria-label="DNS Records Table" className="w-full mt-6 text-left border-collapse">
      <TableHeader columns={columns}>
        {(column) => (
          <TableColumn
            key={column.uid}
            className="bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-200 font-bold py-4 px-6 border-b-2 border-gray-300 dark:border-gray-700"
          >
            {column.name}
          </TableColumn>
        )}
      </TableHeader>
      <TableBody items={filteredRecords}>
        {(record) => (
          <TableRow key={record.type + record.value} className="hover:bg-gray-100 dark:hover:bg-gray-700 transition-all">
            <TableCell className="py-3 px-6 border-b border-gray-300 dark:border-gray-700">{record.type}</TableCell>
            <TableCell className="py-3 px-6 border-b border-gray-300 dark:border-gray-700">{record.value}</TableCell>
            <TableCell className="py-3 px-6 border-b border-gray-300 dark:border-gray-700">{record.ttl}</TableCell>
            <TableCell className="py-3 px-6 border-b border-gray-300 dark:border-gray-700">
              <Progress value={((record.ttl / 86400) * 100)} className="w-full h-2 bg-gray-200 dark:bg-gray-600" />
            </TableCell>
          </TableRow>
        )}
      </TableBody>
    </Table>
  );
};

export default TableSection;
