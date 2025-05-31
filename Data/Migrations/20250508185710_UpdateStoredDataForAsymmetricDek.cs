using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecureDataSharing.Data.Migrations
{
    /// <inheritdoc />
    public partial class UpdateStoredDataForAsymmetricDek : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "EncryptedDekForOwner",
                table: "StoredDatas",
                type: "varbinary(max)",
                nullable: false,
                defaultValue: new byte[0]);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EncryptedDekForOwner",
                table: "StoredDatas");
        }
    }
}
