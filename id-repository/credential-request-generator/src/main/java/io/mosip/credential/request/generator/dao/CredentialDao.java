package io.mosip.credential.request.generator.dao;

import io.mosip.credential.request.generator.entity.CredentialEntity;
import io.mosip.credential.request.generator.repositary.CredentialRepositary;
import io.mosip.idrepository.core.logger.IdRepoLogger;
import io.mosip.idrepository.core.security.IdRepoSecurityManager;
import io.mosip.kernel.core.logger.spi.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Component
public class CredentialDao {

    @Value("${credential.batch.status:NEW}")
    private String status;

    @Value("${credential.batch.page.size:100}")
    private int pageSize;
    

    @Value("${credential.request.reprocess.statuscodes}")
    private String reprocessStatusCodes;
    

    private static final Logger LOGGER = IdRepoLogger.getLogger(CredentialDao.class);

    /** The crdential repo. */
    @Autowired
    private CredentialRepositary<CredentialEntity, String> crdentialRepo;

    public void update(String batchId, List<CredentialEntity> credentialEntities) {
        crdentialRepo.saveAll(credentialEntities);
        LOGGER.info(IdRepoSecurityManager.getUser(), "CredentialDao", "batchid = " + batchId,
                "Record updated successfully. Total records : " + credentialEntities.size());
    }

//    public List<CredentialRequestStatus> getCredentials(String batchId) {
    public List<CredentialEntity> getCredentials(String batchId) {

        LOGGER.info(IdRepoSecurityManager.getUser(), "CredentialDao", "batchid = " + batchId,
                "Inside getCredentials() method");

        long startTime = System.currentTimeMillis();
        List<CredentialEntity> credentialEntities = crdentialRepo.findCredentialByStatusCode(status, pageSize);
        long endTime = System.currentTimeMillis();

        LOGGER.info(IdRepoSecurityManager.getUser(), "CredentialDao", "batchid = " + batchId,
                "Total records picked from credential_transaction table for processing is " + credentialEntities.size() + " (" + (endTime - startTime) + "ms)");
       
        return ((credentialEntities != null && credentialEntities.size() > 0) ? credentialEntities : new ArrayList<>());
    }

    public List<CredentialEntity> getCredentialsForReprocess(String batchId) {
        LOGGER.info(IdRepoSecurityManager.getUser(), "CredentialDao", "batchid = " + batchId,
                "Inside getCredentialsForReprocess() method");
        String[] statusCodes = reprocessStatusCodes.split(",");
        List<CredentialEntity> credentialEntities =  crdentialRepo.findCredentialByStatusCodes(statusCodes, pageSize);

        LOGGER.info(IdRepoSecurityManager.getUser(), "CredentialDao", "batchid = " + batchId,
                "Total records picked from credential_transaction table for reprocessing is " + credentialEntities.size());

        return ((credentialEntities != null && credentialEntities.size() > 0) ? credentialEntities : new ArrayList<>());
    }

    public Page<CredentialEntity> findByStatusCode(String statusCode, Pageable pageable){

      return crdentialRepo.findByStatusCode(statusCode, pageable);
    }
    
    public Page<CredentialEntity> findByStatusCodeWithEffectiveDtimes(String statusCode,
			 LocalDateTime effectiveDTimes,
			Pageable pageable){
    	return crdentialRepo.findByStatusCodeWithEffectiveDtimes(statusCode, effectiveDTimes, pageable);
    }


	public void save(CredentialEntity credential) {
		crdentialRepo.save(credential);
		 LOGGER.info(IdRepoSecurityManager.getUser(), "CredentialDao", "requestId = " + credential.getRequestId(),
	                "Record saved successfully.");
	}


	public void update(CredentialEntity credential) {
		crdentialRepo.save(credential);
		 LOGGER.info(IdRepoSecurityManager.getUser(), "CredentialDao", "requestId = " + credential.getRequestId(),
	                "Record updated successfully.");
	}


	public Optional<CredentialEntity> findById(String requestId) {
		return crdentialRepo.findById(requestId);
		
	}
}