using System;
using System.Linq;
using System.Threading.Tasks;
using BlackBarLabs.Collections.Async;
using BlackBarLabs.Persistence.Azure;
using BlackBarLabs.Persistence.Azure.StorageTables;

namespace BlackBarLabs.Security.SessionServer.Persistence.Azure.Documents
{
    internal class AuthorizationDocument : Microsoft.WindowsAzure.Storage.Table.TableEntity
    {
        #region Constructors

        public AuthorizationDocument() { }

        internal IEnumerableAsync<ClaimDelegate> GetClaims(AzureStorageRepository repository)
        {
            return EnumerableAsync.YieldAsync<ClaimDelegate>(
                async (yieldAsync) =>
                {
                    var claimDocumentIds = Claims.ToGuidsFromByteArray();
                    foreach (var claimDocumentId in claimDocumentIds)
                    {
                        await await repository.FindByIdAsync(claimDocumentId,
                            async (ClaimDocument claimsDoc) =>
                            {
                                Uri issuer;
                                Uri.TryCreate(claimsDoc.Issuer, UriKind.RelativeOrAbsolute, out issuer);
                                Uri type;
                                Uri.TryCreate(claimsDoc.Type, UriKind.RelativeOrAbsolute, out type);
                                await yieldAsync(claimsDoc.ClaimId, issuer, type, claimsDoc.Value);
                            },
                            async () =>
                            {
                                // TODO: Flag data inconsitency
                                await Task.FromResult(true);
                            });
                    }
                });
        }

        #endregion

        #region Properties

        public byte [] Claims { get; set; }
        
        internal async Task<TResult> AddClaimsAsync<TResult>(ClaimDocument claimsDoc, AzureStorageRepository repository,
            Func<TResult> success,
            Func<TResult> failure)
        {
            var claimDocumentIdsCurrent = Claims.ToGuidsFromByteArray();
            var claimDocumentIds = claimDocumentIdsCurrent.Concat(new Guid[] { claimsDoc.ClaimId });
            this.Claims = claimDocumentIds.ToByteArrayOfGuids();
            return await repository.CreateAsync(claimsDoc.ClaimId, claimsDoc,
                        () => success(),
                        () => failure());
        }

        #endregion

    }
}
