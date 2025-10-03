using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AdicionarCorIrisMarca : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Cor",
                table: "IrisMarcas",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 2, 21, 11, 43, 475, DateTimeKind.Utc).AddTicks(5589));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 17, 21, 11, 43, 475, DateTimeKind.Utc).AddTicks(5599));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 25, 21, 11, 43, 475, DateTimeKind.Utc).AddTicks(5603));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 2, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(5983), new DateTime(2025, 9, 2, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(5971) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 9, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(5992), new DateTime(2025, 9, 9, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(5988) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 22, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6000), new DateTime(2025, 9, 22, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(5996) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 17, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6008), new DateTime(2025, 9, 17, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6004) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 1, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6015), new DateTime(2025, 10, 1, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6012) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6022), new DateTime(2025, 9, 27, 22, 11, 43, 475, DateTimeKind.Local).AddTicks(6019) });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Cor",
                table: "IrisMarcas");

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 2, 16, 17, 21, 896, DateTimeKind.Utc).AddTicks(9542));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 17, 16, 17, 21, 896, DateTimeKind.Utc).AddTicks(9554));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 25, 16, 17, 21, 896, DateTimeKind.Utc).AddTicks(9560));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 2, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(870), new DateTime(2025, 9, 2, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(856) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 9, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(893), new DateTime(2025, 9, 9, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(878) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 22, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(917), new DateTime(2025, 9, 22, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(913) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 17, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(947), new DateTime(2025, 9, 17, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(936) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 1, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(960), new DateTime(2025, 10, 1, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(955) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(999), new DateTime(2025, 9, 27, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(993) });
        }
    }
}
