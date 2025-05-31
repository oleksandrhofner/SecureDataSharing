using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecureDataSharing.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddEncryptedDekToDataPermissions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<byte[]>(
                name: "EncryptedDekForRecipient",
                table: "DataPermissions",
                type: "varbinary(max)",
                nullable: false,
                defaultValue: new byte[0]);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EncryptedDekForRecipient",
                table: "DataPermissions");
        }
    }
}
